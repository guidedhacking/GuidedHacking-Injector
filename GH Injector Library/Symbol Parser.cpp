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
	m_hInterruptEvent	= CreateEvent(nullptr, TRUE, FALSE, nullptr);
	m_fProgress			= 0.0f;
	m_bStartDownload	= false;
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
	LOG("  SYMBOL_PARSER::VerifyExistingPdb called\n");

	std::ifstream f(m_szPdbPath.c_str(), std::ios::binary | std::ios::ate);
	if (f.bad())
	{
		LOG("   Symbol Parser: failed to open PDB for verification\n");

		return false;
	}

	size_t size_on_disk = static_cast<size_t>(f.tellg());
	if (!size_on_disk)
	{
		f.close();

		LOG("   Symbol Parser: invaild file size\n");

		return false;
	}

	char * pdb_raw = new char[size_on_disk];
	if (!pdb_raw)
	{
		f.close();

		LOG("   Symbol Parser: failed to allocate memory\n");

		return false;
	}

	f.seekg(std::ios::beg);
	f.read(pdb_raw, size_on_disk);
	f.close();

	LOG("   Symbol Parser: PDB loaded into memory\n");

	if (size_on_disk < sizeof(PDBHeader7))
	{
		delete[] pdb_raw;

		LOG("   Symbol Parser: raw size smaller than PDBHeader7\n");

		return false;
	}

	auto * pPDBHeader = ReCa<PDBHeader7*>(pdb_raw);

	if (memcmp(pPDBHeader->signature, "Microsoft C/C++ MSF 7.00\r\n\x1A""DS\0\0\0", sizeof(PDBHeader7::signature)))
	{
		delete[] pdb_raw;

		LOG("   Symbol Parser: PDB signature mismatch\n");

		return false;
	}

	if (size_on_disk < (size_t)pPDBHeader->page_size * pPDBHeader->file_page_count)
	{
		delete[] pdb_raw;

		LOG("   Symbol Parser: PDB size smaller than page_size * page_count\n");

		return false;
	}

	LOG("   Symbol Parser: PDB size validated\n");

	int		* pRootPageNumber	= ReCa<int*>(pdb_raw + (size_t)pPDBHeader->root_stream_page_number_list_number * pPDBHeader->page_size);
	auto	* pRootStream		= ReCa<RootStream7*>(pdb_raw + (size_t)(*pRootPageNumber) * pPDBHeader->page_size);

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


	LOG("   Symbol Parser: PDB size parsed\n");

	auto pdb_info_page_index = streams.at(1).at(0);

	auto * stream_data = ReCa<GUID_StreamData*>(pdb_raw + (size_t)(pdb_info_page_index) * pPDBHeader->page_size);

	int guid_eq = memcmp(&stream_data->guid, &guid, sizeof(GUID));

	delete[] pdb_raw;
	
	auto ret = (guid_eq == 0);

	if (ret)
	{
		LOG("   Symbol Parser: guid match\n");
	}
	else
	{
		LOG("   Symbol Parser: guid mismatch\n");
	}

	return ret;
}

DWORD SYMBOL_PARSER::Initialize(const std::wstring szModulePath, const std::wstring path, std::wstring * pdb_path_out, bool Redownload, bool WaitForConnection, bool AutoDownload)
{
	if (AutoDownload)
	{
		m_bStartDownload = true;
	}
	else
	{
		m_bStartDownload = false;
	}

	LOG("SYMBOL_PARSER::Initialize called in thread %08X (%d)\n", GetCurrentThreadId(), GetCurrentThreadId());

	if (m_Ready)
	{
		LOG(" Symbol Parser: already initialized\n");

		return SYMBOL_ERR_SUCCESS;
	}

	std::ifstream File(szModulePath.c_str(), std::ios::binary | std::ios::ate);
	if (!File.good())
	{
		LOG(" Symbol Parser: can't open module path\n");

		return SYMBOL_ERR_CANT_OPEN_MODULE;
	}

	auto FileSize = File.tellg();
	if (!FileSize)
	{
		LOG(" Symbol Parser: invalid file size\n");

		return SYMBOL_ERR_FILE_SIZE_IS_NULL;
	}

	BYTE * pRawData = new BYTE[static_cast<size_t>(FileSize)];
	if (!pRawData)
	{
		delete[] pRawData;

		File.close();

		LOG(" Symbol Parser: can't allocate memory\n");

		return SYMBOL_ERR_CANT_ALLOC_MEMORY_NEW;
	}

	File.seekg(0, std::ios::beg);
	File.read(ReCa<char*>(pRawData), FileSize);
	File.close();

	LOG(" Symbol Parser: ready to parse PE headers\n");

	IMAGE_DOS_HEADER	* pDos	= ReCa<IMAGE_DOS_HEADER*>(pRawData);
	IMAGE_NT_HEADERS	* pNT	= ReCa<IMAGE_NT_HEADERS*>(pRawData + pDos->e_lfanew);
	IMAGE_FILE_HEADER	* pFile = &pNT->FileHeader;

	IMAGE_OPTIONAL_HEADER64 * pOpt64 = nullptr;
	IMAGE_OPTIONAL_HEADER32 * pOpt32 = nullptr;

	bool x86 = false;

	if (pFile->Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		pOpt64 = ReCa<IMAGE_OPTIONAL_HEADER64*>(&pNT->OptionalHeader);

		LOG(" Symbol Parser: x64 target identified\n");
	}
	else if (pFile->Machine == IMAGE_FILE_MACHINE_I386)
	{
		pOpt32 = ReCa<IMAGE_OPTIONAL_HEADER32*>(&pNT->OptionalHeader);
		x86 = true;

		LOG(" Symbol Parser: x86 target identified\n");
	}
	else
	{
		delete[] pRawData;

		LOG(" Symbol Parser: invalid file architecture\n");

		return SYMBOL_ERR_INVALID_FILE_ARCHITECTURE;
	}

	DWORD ImageSize = x86 ? pOpt32->SizeOfImage : pOpt64->SizeOfImage;
	BYTE * pLocalImageBase = ReCa<BYTE*>(VirtualAlloc(nullptr, ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pLocalImageBase)
	{
		delete[] pRawData;

		LOG(" Symbol Parser: can't allocate memory: 0x%08X\n", GetLastError());

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
	
	LOG(" Symbol Parser: sections mapped\n");

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

		LOG(" Symbol Parser: no PDB debug data\n");

		return SYMBOL_ERR_NO_PDB_DEBUG_DATA;
	}

	PdbInfo * pdb_info = ReCa<PdbInfo*>(pLocalImageBase + pDebugDir->AddressOfRawData);
	if (pdb_info->Signature != 0x53445352)
	{
		VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

		delete[] pRawData;

		LOG(" Symbol Parser: invalid PDB signature\n");

		return SYMBOL_ERR_NO_PDB_DEBUG_DATA;
	}
	
	m_szPdbPath = path;
	
	if (m_szPdbPath[m_szPdbPath.length() - 1] != '\\')
	{
		m_szPdbPath += '\\';
	}

	LOG(" Symbol Parser: PDB signature identified\n");

	if (!CreateDirectoryW(m_szPdbPath.c_str(), nullptr))
	{
		if (GetLastError() != ERROR_ALREADY_EXISTS)
		{
			LOG(" Symbol Parser: can't create/open download path: 0x%08X\n", GetLastError());

			return SYMBOL_ERR_PATH_DOESNT_EXIST;
		}
	}

	m_szPdbPath += x86 ? L"x86\\" : L"x64\\";

	if (!CreateDirectoryW(m_szPdbPath.c_str(), nullptr))
	{
		if (GetLastError() != ERROR_ALREADY_EXISTS)
		{
			LOG(" Symbol Parser: can't create/open download path: 0x%08X\n", GetLastError());

			return SYMBOL_ERR_CANT_CREATE_DIRECTORY;
		}
	}

	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> conv;

	std::wstring szPdbFileName(conv.from_bytes(pdb_info->PdbFileName));
	m_szPdbPath += szPdbFileName;

	LOG(" Symbol Parser: PDB path = %ls\n", m_szPdbPath.c_str());
		
	DWORD Filesize = 0;
	WIN32_FILE_ATTRIBUTE_DATA file_attr_data{ 0 };
	if (GetFileAttributesExW(m_szPdbPath.c_str(), GetFileExInfoStandard, &file_attr_data))
	{
		Filesize = file_attr_data.nFileSizeLow;

		if (!Redownload && !VerifyExistingPdb(pdb_info->Guid))
		{
			LOG(" Symbol Parser: verification failed, PDB will be redownloaded\n");

			Redownload = true;
		}

		if (Redownload)
		{
			DeleteFileW(m_szPdbPath.c_str());
		}
	}	
	else
	{
		LOG(" Symbol Parser: file doesn't exist, PDB will be downloaded\n");

		Redownload = true;
	}

	if (Redownload)
	{
		wchar_t w_GUID[100]{ 0 };
		if (!StringFromGUID2(pdb_info->Guid, w_GUID, 100))
		{
			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

			delete[] pRawData;

			LOG(" Symbol Parser: failed to parse GUID");

			return SYMBOL_ERR_CANT_CONVERT_PDB_GUID;
		}

		LOG(" Symbol Parser: GUID = %ls\n", w_GUID);

		std::wstring guid_filtered;
		for (UINT i = 0; w_GUID[i]; ++i)
		{
			if ((w_GUID[i] >= '0' && w_GUID[i] <= '9') || (w_GUID[i] >= 'A' && w_GUID[i] <= 'F') || (w_GUID[i] >= 'a' && w_GUID[i] <= 'f'))
			{
				guid_filtered += w_GUID[i];
			}
		}

		std::wstring url = L"https://msdl.microsoft.com/download/symbols/";
		url += szPdbFileName;
		url += '/';
		url += guid_filtered;
		url += std::to_wstring(pdb_info->Age);
		url += '/';
		url += szPdbFileName;

		LOG(" Symbol Parser: URL = %ls\n", url.c_str());

		if (WaitForConnection)
		{
			LOG(" Symbol Parser: checking internet connection\n");

			while (InternetCheckConnectionW(L"https://msdl.microsoft.com", FLAG_ICC_FORCE_CONNECTION, NULL) == FALSE)
			{
				Sleep(25);

				if (m_bInterruptEvent)
				{
					VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

					delete[] pRawData;

					LOG(" Symbol Parser: interrupt event triggered\n");

					return SYMBOL_ERR_INTERRUPT;
				}
			}

			LOG(" Symbol Parser: connection verified\n");
		}

		wchar_t szCacheFile[MAX_PATH]{ 0 };

		if (m_hInterruptEvent)
		{
			m_DlMgr.SetInterruptEvent(m_hInterruptEvent);
		}

		if (!m_bStartDownload)
		{
			LOG(" Symbol Parser: waiting for download start\n");
		}

		while (!m_bStartDownload && !m_bInterruptEvent)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}

		if (m_bInterruptEvent)
		{
			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

			delete[] pRawData;

			LOG(" Symbol Parser: download interrupted\n");

			return SYMBOL_ERR_INTERRUPT;
		}

		LOG(" Symbol Parser: downloading PDB\n");

		auto hr = URLDownloadToCacheFileW(nullptr, url.c_str(), szCacheFile, sizeof(szCacheFile) / sizeof(szCacheFile[0]), NULL, &m_DlMgr);
		if (FAILED(hr))
		{
			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

			delete[] pRawData;

			LOG(" Symbol Parser: failed to download file: 0x%08X\n", hr);

			return SYMBOL_ERR_DOWNLOAD_FAILED;
		}

		LOG(" Symbol Parser: download finished\n");

		if (!CopyFileW(szCacheFile, m_szPdbPath.c_str(), FALSE))
		{
			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

			delete[] pRawData;

			LOG(" Symbol Parser: failed to copy file into working directory: 0x%08X\n", GetLastError());

			return SYMBOL_ERR_COPYFILE_FAILED;
		}

		DeleteFileW(szCacheFile);
	}

	m_fProgress = 1.0f;

	VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

	delete[] pRawData;

	LOG(" Symbol Parser: PDB verified\n");

	if (!Filesize)
	{
		if (!GetFileAttributesExW(m_szPdbPath.c_str(), GetFileExInfoStandard, &file_attr_data))
		{
			LOG(" Symbol Parser: can't access PDB file: 0x%08X\n", GetLastError());

			return SYMBOL_ERR_CANT_ACCESS_PDB_FILE;
		}

		Filesize = file_attr_data.nFileSizeLow;
	}

	m_hPdbFile = CreateFileW(m_szPdbPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, NULL, nullptr);
	if (m_hPdbFile == INVALID_HANDLE_VALUE)
	{
		LOG(" Symbol Parser: can't open PDB file: 0x%08X\n", GetLastError());

		return SYMBOL_ERR_CANT_OPEN_PDB_FILE;
	}

	m_hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
	if (!m_hProcess)
	{
		CloseHandle(m_hPdbFile);

		LOG(" Symbol Parser: can't open current process: 0x%08X\n", GetLastError());

		return SYMBOL_ERR_CANT_OPEN_PROCESS;
	}

	if (!SymInitializeW(m_hProcess, m_szPdbPath.c_str(), FALSE))
	{
		CloseHandle(m_hProcess);
		CloseHandle(m_hPdbFile);

		LOG(" Symbol Parser: SymInitializeW failed: 0x%08X\n", GetLastError());

		return SYMBOL_ERR_SYM_INIT_FAIL;
	}

	m_Initialized = true;

	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_AUTO_PUBLICS);

	m_SymbolTable = SymLoadModuleExW(m_hProcess, nullptr, m_szPdbPath.c_str(), nullptr, 0x10000000, Filesize, nullptr, NULL);
	if (!m_SymbolTable)
	{
		SymCleanup(m_hProcess);

		CloseHandle(m_hProcess);
		CloseHandle(m_hPdbFile);

		LOG(" Symbol Parser: SymLoadModuleExW failed: 0x%08X\n", GetLastError());

		return SYMBOL_ERR_SYM_LOAD_TABLE;
	}

	if (pdb_path_out)
	{
		*pdb_path_out = m_szPdbPath;
	}

	m_Ready = true;

	LOG(" Symbol Parser: initialization finished\n");

	return SYMBOL_ERR_SUCCESS;
}

DWORD SYMBOL_PARSER::GetSymbolAddress(const char * szSymbolName, DWORD & RvaOut)
{
	if (!m_Ready)
	{
		LOG("     Symbol Parser: not ready\n");

		return SYMBOL_ERR_NOT_INITIALIZED;
	}

	if (!szSymbolName)
	{
		LOG("     Symbol Parser: invalid symbol name\n");

		return SYMBOL_ERR_IVNALID_SYMBOL_NAME;
	}

	SYMBOL_INFO si{ 0 };
	si.SizeOfStruct = sizeof(SYMBOL_INFO);
	if (!SymFromName(m_hProcess, szSymbolName, &si))
	{
		LOG("     Symbol Parser: search failed: 0x%08X\n", GetLastError());

		return SYMBOL_ERR_SYMBOL_SEARCH_FAILED;
	}

	RvaOut = (DWORD)(si.Address - si.ModBase);

	LOG("     Symbol Parser: RVA %08X -> %s\n", RvaOut, szSymbolName);

	return SYMBOL_ERR_SUCCESS;
}

void SYMBOL_PARSER::SetDownload(bool bDownload)
{
	m_bStartDownload = bDownload;
}

void SYMBOL_PARSER::Interrupt()
{
	LOG("Symbol Parser: Interrupt\n");

	m_bInterruptEvent = true;

	if (m_hInterruptEvent)
	{
		if (!SetEvent(m_hInterruptEvent))
		{
			LOG(" Symbol Parser: SetEvent failed to trigger interrupt event: %08X\n", GetLastError());
		}
		else
		{
			LOG(" Symbol Parser: interrupt event set\n");
		}
	}
	else
	{
		LOG(" Symbol Parser: no interrupt event specified\n");
	}

	m_Initialized	= false;
	m_Ready			= false;
}

float SYMBOL_PARSER::GetDownloadProgress()
{
	if (m_fProgress == 1.0f)
	{
		return m_fProgress;
	}

	return m_DlMgr.GetDownloadProgress();
}