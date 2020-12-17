#include "pch.h"

#include "Symbol Parser.h"

SYMBOL_PARSER::SYMBOL_PARSER()
{
	m_Initialized	= false;
	m_Ready			= false;
	m_SymbolTable	= 0;
	m_hPdbFile		= nullptr;
	m_hProcess		= nullptr;

	m_bInterruptEvent	= false;
	m_hInterruptEvent	= CreateEvent(nullptr, FALSE, FALSE, nullptr);
	m_fProgress			= 0.0f;
}

SYMBOL_PARSER::~SYMBOL_PARSER()
{
	if (m_hInterruptEvent)
	{
		CloseHandle(m_hInterruptEvent);
	}

	if (m_Initialized)
	{
		if (m_SymbolTable)
		{
			SymUnloadModule64(m_hProcess, m_SymbolTable);
		}

		SymCleanup(m_hProcess);
	}

	if (m_hProcess)
	{
		CloseHandle(m_hProcess);
	}

	if (m_hPdbFile)
	{
		CloseHandle(m_hPdbFile);
	}
}

bool SYMBOL_PARSER::VerifyExistingPdb(const GUID & guid)
{
	std::ifstream f(m_szPdbPath.c_str(), std::ios::binary | std::ios::ate);
	if (f.bad())
	{
		return false;
	}

	size_t size_on_disk = static_cast<size_t>(f.tellg());
	if (!size_on_disk)
	{
		f.close();

		return false;
	}

	char * pdb_raw = new char[size_on_disk];
	if (!pdb_raw)
	{
		f.close();

		return false;
	}

	f.seekg(std::ios::beg);
	f.read(pdb_raw, size_on_disk);
	f.close();

	if (size_on_disk < sizeof(PDBHeader7))
	{
		delete[] pdb_raw;

		return false;
	}

	auto * pPDBHeader = ReCa<PDBHeader7*>(pdb_raw);

	if (memcmp(pPDBHeader->signature, "Microsoft C/C++ MSF 7.00\r\n\x1A""DS\0\0\0", sizeof(PDBHeader7::signature)))
	{
		delete[] pdb_raw;

		return false;
	}

	if (size_on_disk < (size_t)pPDBHeader->page_size * pPDBHeader->file_page_count)
	{
		delete[] pdb_raw;

		return false;
	}

	int		* pRootPageNumber	= ReCa<int*>(pdb_raw + (size_t)pPDBHeader->root_stream_page_number_list_number * pPDBHeader->page_size);
	auto	* pRootStream		= ReCa<RootStream7*>(pdb_raw + (size_t)(*pRootPageNumber) * pPDBHeader->page_size);

	int size = 0;
	for (int i = 0; i < pRootStream->num_streams; ++i)
	{
		if (pRootStream->stream_sizes[i] == 0xFFFFFFFF)
			continue;

		size += pRootStream->stream_sizes[i];
	}
	
	std::map<int, std::vector<int>> streams;
	int current_page_number = 0;
	
	for (int i = 0; i != pRootStream->num_streams; ++i)
	{
		int current_size = pRootStream->stream_sizes[i] == 0xFFFFFFFF ? 0 : pRootStream->stream_sizes[i];

		int current_page_count = current_size / pPDBHeader->page_size;
		if (current_size % pPDBHeader->page_size)
		{
			++current_page_count;
		}

		std::vector<int> numbers;

		for (int j = 0; j != current_page_count; ++j, ++current_page_number)
		{
			numbers.push_back(pRootStream->stream_sizes[pRootStream->num_streams + current_page_number]);
		}

		streams.insert({ i, numbers });
	}

	auto pdb_info_page_index = streams.at(1).at(0);

	auto * stream_data = ReCa<GUID_StreamData*>(pdb_raw + (size_t)(pdb_info_page_index) * pPDBHeader->page_size);

	int guid_eq = memcmp(&stream_data->guid, &guid, sizeof(GUID));

	delete[] pdb_raw;
	
	return (guid_eq == 0);
}

DWORD SYMBOL_PARSER::Initialize(const std::string szModulePath, const std::string path, std::string * pdb_path_out, bool Redownload, bool WaitForConnection)
{
	if (m_Ready)
	{
		return SYMBOL_ERR_ALREADY_INITIALIZED;
	}

	m_bInterruptEvent = false;

	std::ifstream File(szModulePath, std::ios::binary | std::ios::ate);
	if (!File.good())
	{
		return SYMBOL_ERR_CANT_OPEN_MODULE;
	}

	auto FileSize = File.tellg();
	if (!FileSize)
	{
		return SYMBOL_ERR_FILE_SIZE_IS_NULL;
	}

	BYTE * pRawData = new BYTE[static_cast<size_t>(FileSize)];
	if (!pRawData)
	{
		delete[] pRawData;

		File.close();

		return SYMBOL_ERR_CANT_ALLOC_MEMORY_NEW;
	}

	File.seekg(0, std::ios::beg);
	File.read(ReCa<char*>(pRawData), FileSize);
	File.close();

	IMAGE_DOS_HEADER	* pDos	= ReCa<IMAGE_DOS_HEADER*>(pRawData);
	IMAGE_NT_HEADERS	* pNT	= ReCa<IMAGE_NT_HEADERS*>(pRawData + pDos->e_lfanew);
	IMAGE_FILE_HEADER	* pFile = &pNT->FileHeader;

	IMAGE_OPTIONAL_HEADER64 * pOpt64 = nullptr;
	IMAGE_OPTIONAL_HEADER32 * pOpt32 = nullptr;

	bool x86 = false;

	if (pFile->Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		pOpt64 = ReCa<IMAGE_OPTIONAL_HEADER64*>(&pNT->OptionalHeader);
	}
	else if (pFile->Machine == IMAGE_FILE_MACHINE_I386)
	{
		pOpt32 = ReCa<IMAGE_OPTIONAL_HEADER32*>(&pNT->OptionalHeader);
		x86 = true;
	}
	else
	{
		delete[] pRawData;

		return SYMBOL_ERR_INVALID_FILE_ARCHITECTURE;
	}

	DWORD ImageSize = x86 ? pOpt32->SizeOfImage : pOpt64->SizeOfImage;
	BYTE * pLocalImageBase = ReCa<BYTE*>(VirtualAlloc(nullptr, ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pLocalImageBase)
	{
		delete[] pRawData;

		return SYMBOL_ERR_CANT_ALLOC_MEMORY;
	}

	memcpy(pLocalImageBase, pRawData, x86 ? pOpt32->SizeOfHeaders : pOpt64->SizeOfHeaders);

	auto * pCurrentSectionHeader = IMAGE_FIRST_SECTION(pNT);
	for (UINT i = 0; i != pFile->NumberOfSections; ++i, ++pCurrentSectionHeader)
	{
		if (pCurrentSectionHeader->SizeOfRawData)
		{
			memcpy(pLocalImageBase + pCurrentSectionHeader->VirtualAddress, pRawData + pCurrentSectionHeader->PointerToRawData, pCurrentSectionHeader->SizeOfRawData);
		}
	}

	IMAGE_DATA_DIRECTORY * pDataDir = nullptr;
	if (x86)
	{
		pDataDir = &pOpt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	}
	else
	{
		pDataDir = &pOpt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	}

	IMAGE_DEBUG_DIRECTORY * pDebugDir = ReCa<IMAGE_DEBUG_DIRECTORY*>(pLocalImageBase + pDataDir->VirtualAddress);

	if (!pDataDir->Size || IMAGE_DEBUG_TYPE_CODEVIEW != pDebugDir->Type)
	{
		VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

		delete[] pRawData;

		return SYMBOL_ERR_NO_PDB_DEBUG_DATA;
	}

	PdbInfo * pdb_info = ReCa<PdbInfo*>(pLocalImageBase + pDebugDir->AddressOfRawData);
	if (pdb_info->Signature != 0x53445352)
	{
		VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

		delete[] pRawData;

		return SYMBOL_ERR_NO_PDB_DEBUG_DATA;
	}
	
	m_szPdbPath = path;
	
	if (m_szPdbPath[m_szPdbPath.length() - 1] != '\\')
	{
		m_szPdbPath += '\\';
	}

	if (!CreateDirectoryA(m_szPdbPath.c_str(), nullptr))
	{
		if (GetLastError() != ERROR_ALREADY_EXISTS)
		{
			return SYMBOL_ERR_PATH_DOESNT_EXIST;
		}
	}

	m_szPdbPath += x86 ? "x86\\" : "x64\\";

	if (!CreateDirectoryA(m_szPdbPath.c_str(), nullptr))
	{
		if (GetLastError() != ERROR_ALREADY_EXISTS)
		{
			return SYMBOL_ERR_CANT_CREATE_DIRECTORY;
		}
	}

	m_szPdbPath += pdb_info->PdbFileName;
		
	DWORD Filesize = 0;
	WIN32_FILE_ATTRIBUTE_DATA file_attr_data{ 0 };
	if (GetFileAttributesExA(m_szPdbPath.c_str(), GetFileExInfoStandard, &file_attr_data))
	{
		Filesize = file_attr_data.nFileSizeLow;

		if (!Redownload && !VerifyExistingPdb(pdb_info->Guid))
		{
			Redownload = true;
		}

		if (Redownload)
		{
			DeleteFileA(m_szPdbPath.c_str());
		}
	}	
	else
	{
		Redownload = true;
	}

	if (Redownload)
	{
		wchar_t w_GUID[100]{ 0 };
		if (!StringFromGUID2(pdb_info->Guid, w_GUID, 100))
		{
			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

			delete[] pRawData;

			return SYMBOL_ERR_CANT_CONVERT_PDB_GUID;
		}
		
		char a_GUID[100]{ 0 };
		size_t l_GUID = 0;
		if (wcstombs_s(&l_GUID, a_GUID, w_GUID, sizeof(a_GUID)) || !l_GUID)
		{
			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

			delete[] pRawData;

			return SYMBOL_ERR_GUID_TO_ANSI_FAILED;
		}

		std::string guid_filtered;
		for (UINT i = 0; i != l_GUID; ++i)
		{
			if ((a_GUID[i] >= '0' && a_GUID[i] <= '9') || (a_GUID[i] >= 'A' && a_GUID[i] <= 'F') || (a_GUID[i] >= 'a' && a_GUID[i] <= 'f'))
			{
				guid_filtered += a_GUID[i];
			}
		}

		char age[3]{ 0 };
		_itoa_s(pdb_info->Age, age, 10);

		std::string url = "https://msdl.microsoft.com/download/symbols/";
		url += pdb_info->PdbFileName;
		url += '/';
		url += guid_filtered;
		url += age;
		url += '/';
		url += pdb_info->PdbFileName;

		if (WaitForConnection)
		{
			while (InternetCheckConnectionA("https://msdl.microsoft.com", FLAG_ICC_FORCE_CONNECTION, NULL) == FALSE)
			{
				Sleep(25);

				if (m_bInterruptEvent)
				{
					VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

					delete[] pRawData;

					return SYMBOL_ERR_INTERRUPT;
				}
			}
		}

		char szCacheFile[MAX_PATH]{ 0 };

		m_DlMgr.SetInterruptEvent(m_hInterruptEvent);

		if (FAILED(URLDownloadToCacheFileA(nullptr, url.c_str(), szCacheFile, MAX_PATH , NULL, &m_DlMgr)))
		{
			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

			delete[] pRawData;

			return SYMBOL_ERR_DOWNLOAD_FAILED;
		}

		if (!CopyFileA(szCacheFile, m_szPdbPath.c_str(), FALSE))
		{
			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

			delete[] pRawData;

			return SYMBOL_ERR_COPYFILE_FAILED;
		}
	}

	m_fProgress = 1.0f;

	VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

	delete[] pRawData;

	if (!Filesize)
	{
		if (!GetFileAttributesExA(m_szPdbPath.c_str(), GetFileExInfoStandard, &file_attr_data))
		{
			return SYMBOL_ERR_CANT_ACCESS_PDB_FILE;
		}

		Filesize = file_attr_data.nFileSizeLow;
	}

	m_hPdbFile = CreateFileA(m_szPdbPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, NULL, nullptr);
	if (m_hPdbFile == INVALID_HANDLE_VALUE)
	{
		return SYMBOL_ERR_CANT_OPEN_PDB_FILE;
	}

	m_hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
	if (!m_hProcess)
	{
		CloseHandle(m_hPdbFile);

		return SYMBOL_ERR_CANT_OPEN_PROCESS;
	}

	if (!SymInitialize(m_hProcess, m_szPdbPath.c_str(), FALSE))
	{
		CloseHandle(m_hProcess);
		CloseHandle(m_hPdbFile);

		return SYMBOL_ERR_SYM_INIT_FAIL;
	}

	m_Initialized = true;

	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_AUTO_PUBLICS);

	m_SymbolTable = SymLoadModuleEx(m_hProcess, nullptr, m_szPdbPath.c_str(), nullptr, 0x10000000, Filesize, nullptr, NULL);
	if (!m_SymbolTable)
	{
		SymCleanup(m_hProcess);

		CloseHandle(m_hProcess);
		CloseHandle(m_hPdbFile);

		return SYMBOL_ERR_SYM_LOAD_TABLE;
	}

	if (pdb_path_out)
	{
		*pdb_path_out = m_szPdbPath;
	}

	m_Ready = true;

	return SYMBOL_ERR_SUCCESS;
}

DWORD SYMBOL_PARSER::GetSymbolAddress(const char * szSymbolName, DWORD & RvaOut)
{
	if (!m_Ready)
	{
		return SYMBOL_ERR_NOT_INITIALIZED;
	}

	if (!szSymbolName)
	{
		return SYMBOL_ERR_IVNALID_SYMBOL_NAME;
	}

	SYMBOL_INFO si{ 0 };
	si.SizeOfStruct = sizeof(SYMBOL_INFO);
	if (!SymFromName(m_hProcess, szSymbolName, &si))
	{
		return SYMBOL_ERR_SYMBOL_SEARCH_FAILED;
	}

	RvaOut = (DWORD)(si.Address - si.ModBase);

	return SYMBOL_ERR_SUCCESS;
}

void SYMBOL_PARSER::Interrupt()
{
	m_bInterruptEvent = true;

	if (m_hInterruptEvent)
	{
		SetEvent(m_hInterruptEvent);
		CloseHandle(m_hInterruptEvent);
	}

	if (m_Initialized)
	{
		if (m_SymbolTable)
		{
			SymUnloadModule64(m_hProcess, m_SymbolTable);
		}

		SymCleanup(m_hProcess);
	}

	if (m_hProcess)
	{
		CloseHandle(m_hProcess);
	}

	if (m_hPdbFile)
	{
		CloseHandle(m_hPdbFile);
	}
	
	m_Initialized	= false;
	m_Ready			= false;
	m_SymbolTable	= 0;
	m_hPdbFile		= nullptr;
	m_hProcess		= nullptr;

	m_hInterruptEvent = nullptr;
}

float SYMBOL_PARSER::GetDownloadProgress()
{
	if (m_fProgress == 1.0f)
	{
		return m_fProgress;
	}

	return m_DlMgr.GetDownloadProgress();
}