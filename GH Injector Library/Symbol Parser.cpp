#include "pch.h"

#include "SYMBOL Parser.h"

#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "Urlmon.lib")

SYMBOL_PARSER::SYMBOL_PARSER()
{
	m_Initialized = false;
	m_SymbolTable = 0;
	m_Filesize = 0;
	m_hPdbFile = nullptr;
	m_hProcess = nullptr;

}

SYMBOL_PARSER::~SYMBOL_PARSER()
{
	if (m_Initialized)
	{
		SymCleanup(m_hProcess);

		CloseHandle(m_hProcess);
		CloseHandle(m_hPdbFile);

		m_Initialized = false;
	}
}

DWORD SYMBOL_PARSER::Initialize(const char * szModulePath, bool Redownload)
{
	if (m_Initialized)
	{
		return SYMBOL_ERR_ALREADY_INITIALIZED;
	}

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
	File.read(ReCa<char *>(pRawData), FileSize);
	File.close();

	IMAGE_DOS_HEADER * pDos = ReCa<IMAGE_DOS_HEADER *>(pRawData);
	IMAGE_NT_HEADERS * pNT = ReCa<IMAGE_NT_HEADERS *>(pRawData + pDos->e_lfanew);
	IMAGE_FILE_HEADER * pFile = &pNT->FileHeader;

	IMAGE_OPTIONAL_HEADER64 * pOpt64 = nullptr;
	IMAGE_OPTIONAL_HEADER32 * pOpt32 = nullptr;
	bool WoW64 = false;

	if (pFile->Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		pOpt64 = ReCa<IMAGE_OPTIONAL_HEADER64 *>(&pNT->OptionalHeader);
	}
	else if (pFile->Machine == IMAGE_FILE_MACHINE_I386)
	{
		pOpt32 = ReCa<IMAGE_OPTIONAL_HEADER32 *>(&pNT->OptionalHeader);
		WoW64 = true;
	}
	else
	{
		delete[] pRawData;

		return SYMBOL_ERR_INVALID_FILE_ARCHITECTURE;
	}

	DWORD ImageSize = WoW64 ? pOpt32->SizeOfImage : pOpt64->SizeOfImage;
	BYTE * pLocalImageBase = (BYTE *)VirtualAlloc(nullptr, ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pLocalImageBase)
	{
		delete[] pRawData;

		return SYMBOL_ERR_CANT_ALLOC_MEMORY;
	}

	memcpy(pLocalImageBase, pRawData, WoW64 ? pOpt32->SizeOfHeaders : pOpt64->SizeOfHeaders);

	auto * pCurrentSectionHeader = IMAGE_FIRST_SECTION(pNT);
	for (UINT i = 0; i != pFile->NumberOfSections; ++i, ++pCurrentSectionHeader)
	{
		if (pCurrentSectionHeader->SizeOfRawData)
		{
			memcpy(pLocalImageBase + pCurrentSectionHeader->VirtualAddress, pRawData + pCurrentSectionHeader->PointerToRawData, pCurrentSectionHeader->SizeOfRawData);
		}
	}

	IMAGE_DATA_DIRECTORY * pDataDir = nullptr;
	if (WoW64)
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

	char TempPath[MAX_PATH]{ 0 };
	if (!GetTempPathA(sizeof(TempPath), TempPath))
	{
		VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

		delete[] pRawData;

		return SYMBOL_ERR_CANT_GET_TEMP_PATH;
	}

	std::string pdb_path = TempPath;
	pdb_path += "GH Injector\\";
	CreateDirectoryA(pdb_path.c_str(), nullptr);
	pdb_path += WoW64 ? "x86\\" : "x64\\";
	CreateDirectoryA(pdb_path.c_str(), nullptr);
	pdb_path += pdb_info->PdbFileName;

	WIN32_FILE_ATTRIBUTE_DATA file_attr_data{ 0 };
	if (GetFileAttributesExA(pdb_path.c_str(), GetFileExInfoStandard, &file_attr_data) && !Redownload)
	{
		m_Filesize = file_attr_data.nFileSizeLow;
	}
	else
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

		DeleteFileA(pdb_path.c_str());

		if (FAILED(URLDownloadToFileA(nullptr, url.c_str(), pdb_path.c_str(), NULL, nullptr)))
		{
			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

			delete[] pRawData;

			return SYMBOL_ERR_DOWNLOAD_FAILED;
		}
	}

	VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

	delete[] pRawData;

	if (!m_Filesize)
	{
		if (!GetFileAttributesExA(pdb_path.c_str(), GetFileExInfoStandard, &file_attr_data))
		{
			return SYMBOL_ERR_CANT_ACCESS_PDB_FILE;
		}

		m_Filesize = file_attr_data.nFileSizeLow;
	}

	m_szPdbPath = pdb_path;
	m_hPdbFile = CreateFileA(m_szPdbPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, NULL, nullptr);
	if (m_hPdbFile == INVALID_HANDLE_VALUE)
	{
		return SYMBOL_ERR_CANT_OPEN_PDB_FILE;
	}

	m_szModulePath = szModulePath;

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

	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_AUTO_PUBLICS);
	
	m_SymbolTable = SymLoadModuleEx(m_hProcess, nullptr, m_szPdbPath.c_str(), nullptr, 0x10000000, m_Filesize, nullptr, NULL);
	if (!m_SymbolTable)
	{
		SymCleanup(m_hProcess);

		CloseHandle(m_hProcess);
		CloseHandle(m_hPdbFile);

		return SYMBOL_ERR_SYM_LOAD_TABLE;
	}

	m_Initialized = true;

	return SYMBOL_ERR_SUCCESS;
}

DWORD SYMBOL_PARSER::GetSymbolAddress(const char * szSymbolName, DWORD & RvaOut)
{
	if (!m_Initialized)
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