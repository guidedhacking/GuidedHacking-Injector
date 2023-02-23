#include "pch.h"

#include "Symbol Loader.h"

SYMBOL_LOADER::SYMBOL_LOADER()
{
	m_hInterruptEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
}

SYMBOL_LOADER::~SYMBOL_LOADER()
{
	Cleanup();

	if (m_hInterruptEvent)
	{
		CloseHandle(m_hInterruptEvent);
	}
}

bool SYMBOL_LOADER::VerifyExistingPdb(const GUID & guid)
{
	LOG(2, "SYMBOL_LOADER::VerifyExistingPdb called\n");

	std::ifstream f(m_szPdbPath.c_str(), std::ios::binary | std::ios::ate);
	if (f.bad())
	{
		LOG(2, "SYMBOL_LOADER: failed to open PDB for verification\n");

		return false;
	}

	size_t size_on_disk = static_cast<size_t>(f.tellg());
	if (!size_on_disk)
	{
		f.close();

		LOG(2, "SYMBOL_LOADER: invaild file size\n");

		return false;
	}

	char * pdb_raw = new(std::nothrow) char[size_on_disk];
	if (!pdb_raw)
	{
		f.close();

		LOG(2, "SYMBOL_LOADER: failed to allocate memory\n");

		return false;
	}

	f.seekg(std::ios::beg);
	f.read(pdb_raw, size_on_disk);
	f.close();

	LOG(2, "SYMBOL_LOADER: PDB loaded into memory\n");

	if (size_on_disk < sizeof(PDBHeader7))
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: raw size smaller than PDBHeader7\n");

		return false;
	}

	auto * pPDBHeader = ReCa<PDBHeader7*>(pdb_raw);

	if (memcmp(pPDBHeader->signature, "Microsoft C/C++ MSF 7.00\r\n\x1A""DS\0\0\0", sizeof(PDBHeader7::signature)))
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: PDB signature mismatch\n");

		return false;
	}

	if (size_on_disk < (size_t)pPDBHeader->page_size * pPDBHeader->file_page_count)
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: PDB size smaller than page_size * page_count\n");

		return false;
	}

	LOG(2, "SYMBOL_LOADER: PDB size validated\n");

	int		* pRootPageNumber	= ReCa<int *>(pdb_raw + (size_t)pPDBHeader->root_stream_page_number_list_number * pPDBHeader->page_size);
	auto	* pRootStream		= ReCa<RootStream7 *>(pdb_raw + (size_t)(*pRootPageNumber) * pPDBHeader->page_size);

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


	LOG(2, "SYMBOL_LOADER: PDB size parsed\n");

	auto pdb_info_page_index = streams.at(1).at(0);

	auto * stream_data = ReCa<GUID_StreamData *>(pdb_raw + (size_t)(pdb_info_page_index) * pPDBHeader->page_size);

	int guid_eq = memcmp(&stream_data->guid, &guid, sizeof(GUID));

	delete[] pdb_raw;
	
	auto ret = (guid_eq == 0);

	if (ret)
	{
		LOG(2, "SYMBOL_LOADER: guid match\n");
	}
	else
	{
		LOG(2, "SYMBOL_LOADER: guid mismatch\n");
	}

	return ret;
}

DWORD SYMBOL_LOADER::Initialize(const std::wstring & szModulePath, const std::wstring & path, std::wstring * pdb_path_out, bool Redownload, bool WaitForConnection, bool AutoDownload)
{
	Cleanup();

	if (AutoDownload)
	{
		m_bStartDownload = true;
	}

	LOG(1, "SYMBOL_LOADER::Initialize called in thread %08X (%d)\n", GetCurrentThreadId(), GetCurrentThreadId());

	std::ifstream File(szModulePath.c_str(), std::ios::binary | std::ios::ate);
	if (!File.good())
	{
		LOG(1, "SYMBOL_LOADER: can't open module path\n");

		return SYMBOL_ERR_CANT_OPEN_MODULE;
	}

	auto FileSize = File.tellg();
	if (!FileSize)
	{
		LOG(1, "SYMBOL_LOADER: invalid file size\n");

		return SYMBOL_ERR_FILE_SIZE_IS_NULL;
	}

	BYTE * pRawData = new(std::nothrow) BYTE[static_cast<size_t>(FileSize)];
	if (!pRawData)
	{
		delete[] pRawData;

		File.close();

		LOG(1, "SYMBOL_LOADER: can't allocate memory\n");

		return SYMBOL_ERR_CANT_ALLOC_MEMORY_NEW;
	}

	File.seekg(0, std::ios::beg);
	File.read(ReCa<char *>(pRawData), FileSize);
	File.close();

	LOG(1, "SYMBOL_LOADER: ready to parse PE headers\n");

	IMAGE_DOS_HEADER	* pDos	= ReCa<IMAGE_DOS_HEADER *>(pRawData);
	IMAGE_NT_HEADERS	* pNT	= ReCa<IMAGE_NT_HEADERS *>(pRawData + pDos->e_lfanew);
	IMAGE_FILE_HEADER	* pFile = &pNT->FileHeader;

	IMAGE_OPTIONAL_HEADER64 * pOpt64 = nullptr;
	IMAGE_OPTIONAL_HEADER32 * pOpt32 = nullptr;

	bool x86 = false;

	if (pFile->Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		pOpt64 = ReCa<IMAGE_OPTIONAL_HEADER64 *>(&pNT->OptionalHeader);

		LOG(1, "SYMBOL_LOADER: x64 target identified\n");
	}
	else if (pFile->Machine == IMAGE_FILE_MACHINE_I386)
	{
		pOpt32 = ReCa<IMAGE_OPTIONAL_HEADER32 *>(&pNT->OptionalHeader);
		x86 = true;

		LOG(1, "SYMBOL_LOADER: x86 target identified\n");
	}
	else
	{
		delete[] pRawData;

		LOG(1, "SYMBOL_LOADER: invalid file architecture\n");

		return SYMBOL_ERR_INVALID_FILE_ARCHITECTURE;
	}

	DWORD ImageSize = x86 ? pOpt32->SizeOfImage : pOpt64->SizeOfImage;
	BYTE * pLocalImageBase = ReCa<BYTE *>(VirtualAlloc(nullptr, ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pLocalImageBase)
	{
		delete[] pRawData;

		LOG(1, "SYMBOL_LOADER: can't allocate memory: 0x%08X\n", GetLastError());

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
	
	LOG(1, "SYMBOL_LOADER: sections mapped\n");

	IMAGE_DATA_DIRECTORY * pDataDir = nullptr;
	if (x86)
	{
		pDataDir = &pOpt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	}
	else
	{
		pDataDir = &pOpt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	}

	IMAGE_DEBUG_DIRECTORY * pDebugDir = ReCa<IMAGE_DEBUG_DIRECTORY *>(pLocalImageBase + pDataDir->VirtualAddress);

	if (!pDataDir->Size || IMAGE_DEBUG_TYPE_CODEVIEW != pDebugDir->Type)
	{
		VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

		delete[] pRawData;

		LOG(1, "SYMBOL_LOADER: no PDB debug data\n");

		return SYMBOL_ERR_NO_PDB_DEBUG_DATA;
	}

	PdbInfo * pdb_info = ReCa<PdbInfo *>(pLocalImageBase + pDebugDir->AddressOfRawData);
	if (pdb_info->Signature != 0x53445352)
	{
		VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

		delete[] pRawData;

		LOG(1, "SYMBOL_LOADER: invalid PDB signature\n");

		return SYMBOL_ERR_NO_PDB_DEBUG_DATA;
	}
	
	m_szPdbPath = path;
	
	if (m_szPdbPath[m_szPdbPath.length() - 1] != '\\')
	{
		m_szPdbPath += '\\';
	}

	LOG(1, "SYMBOL_LOADER: PDB signature identified\n");

	if (!CreateDirectoryW(m_szPdbPath.c_str(), nullptr))
	{
		if (GetLastError() != ERROR_ALREADY_EXISTS)
		{
			LOG(1, "SYMBOL_LOADER: can't create/open download path: 0x%08X\n", GetLastError());

			return SYMBOL_ERR_PATH_DOESNT_EXIST;
		}
	}

	m_szPdbPath += x86 ? L"x86\\" : L"x64\\";

	if (!CreateDirectoryW(m_szPdbPath.c_str(), nullptr))
	{
		if (GetLastError() != ERROR_ALREADY_EXISTS)
		{
			LOG(1, "SYMBOL_LOADER: can't create/open download path: 0x%08X\n", GetLastError());

			return SYMBOL_ERR_CANT_CREATE_DIRECTORY;
		}
	}

	auto PdbFileName = CharArrayToStdWstring(pdb_info->PdbFileName);
	m_szPdbPath += PdbFileName;

	LOG(1, "SYMBOL_LOADER: PDB path = %ls\n", m_szPdbPath.c_str());
		
	m_Filesize = 0;
	WIN32_FILE_ATTRIBUTE_DATA file_attr_data{ 0 };
	if (GetFileAttributesExW(m_szPdbPath.c_str(), GetFileExInfoStandard, &file_attr_data))
	{
		m_Filesize = file_attr_data.nFileSizeLow;

		if (!Redownload && !VerifyExistingPdb(pdb_info->Guid))
		{
			LOG(1, "SYMBOL_LOADER: verification failed, PDB will be redownloaded\n");

			Redownload = true;
		}

		if (Redownload)
		{
			DeleteFileW(m_szPdbPath.c_str());
		}
	}	
	else
	{
		LOG(1, "SYMBOL_LOADER: file doesn't exist, PDB will be downloaded\n");

		Redownload = true;
	}

	if (Redownload)
	{
		wchar_t w_GUID[100]{ 0 };
		if (!StringFromGUID2(pdb_info->Guid, w_GUID, 100))
		{
			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

			delete[] pRawData;

			LOG(1, "SYMBOL_LOADER: failed to parse GUID");

			return SYMBOL_ERR_CANT_CONVERT_PDB_GUID;
		}

		LOG(1, "SYMBOL_LOADER: GUID = %ls\n", w_GUID);

		std::wstring guid_filtered;
		for (UINT i = 0; w_GUID[i]; ++i)
		{
			if ((w_GUID[i] >= '0' && w_GUID[i] <= '9') || (w_GUID[i] >= 'A' && w_GUID[i] <= 'F') || (w_GUID[i] >= 'a' && w_GUID[i] <= 'f'))
			{
				guid_filtered += w_GUID[i];
			}
		}
		
		std::wstring url = L"https://msdl.microsoft.com/download/symbols/";
		url += PdbFileName;
		url += '/';
		url += guid_filtered;
		url += std::to_wstring(pdb_info->Age);
		url += '/';
		url += PdbFileName;

		LOG(1, "SYMBOL_LOADER: URL = %ls\n", url.c_str());

		if (WaitForConnection)
		{
			LOG(1, "SYMBOL_LOADER: checking internet connection\n");

			while (InternetCheckConnectionW(L"https://msdl.microsoft.com", FLAG_ICC_FORCE_CONNECTION, NULL) == FALSE)
			{
				if (GetLastError() == ERROR_INTERNET_CANNOT_CONNECT)
				{
					VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

					delete[] pRawData;

					LOG(1, "SYMBOL_LOADER: cannot connect to Microsoft Symbol Server\n");

					return SYMBOL_ERR_CANNOT_CONNECT;
				}

				Sleep(25);

				if (m_bInterruptEvent)
				{
					VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

					delete[] pRawData;

					LOG(1, "SYMBOL_LOADER: interrupt event triggered\n");

					return SYMBOL_ERR_INTERRUPT;
				}
			}

			LOG(1, "SYMBOL_LOADER: connection verified\n");
		}

		wchar_t szCacheFile[MAX_PATH]{ 0 };

		if (m_hInterruptEvent)
		{
			m_DlMgr.SetInterruptEvent(m_hInterruptEvent);
		}

		if (!m_bStartDownload)
		{
			LOG(1, "SYMBOL_LOADER: waiting for download start\n");
		}

		while (!m_bStartDownload && !m_bInterruptEvent)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}

		if (m_bInterruptEvent)
		{
			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

			delete[] pRawData;

			LOG(1, "SYMBOL_LOADER: download interrupted\n");

			return SYMBOL_ERR_INTERRUPT;
		}

		LOG(1, "SYMBOL_LOADER: downloading PDB\n");

		auto hr = URLDownloadToCacheFileW(nullptr, url.c_str(), szCacheFile, sizeof(szCacheFile) / sizeof(szCacheFile[0]), NULL, &m_DlMgr);
		if (FAILED(hr))
		{
			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

			delete[] pRawData;

			LOG(1, "SYMBOL_LOADER: failed to download file: 0x%08X\n", hr);

			return SYMBOL_ERR_DOWNLOAD_FAILED;
		}

		LOG(1, "SYMBOL_LOADER: download finished\n");

		if (!CopyFileW(szCacheFile, m_szPdbPath.c_str(), FALSE))
		{
			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

			delete[] pRawData;

			LOG(1, "SYMBOL_LOADER: failed to copy file into working directory: 0x%08X\n", GetLastError());

			return SYMBOL_ERR_COPYFILE_FAILED;
		}

		DeleteFileW(szCacheFile);
	}

	m_fProgress = 1.0f;

	VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

	delete[] pRawData;

	LOG(1, "SYMBOL_LOADER: PDB verified\n");

	if (!m_Filesize)
	{
		if (!GetFileAttributesExW(m_szPdbPath.c_str(), GetFileExInfoStandard, &file_attr_data))
		{
			LOG(1, "SYMBOL_LOADER: can't access PDB file: 0x%08X\n", GetLastError());

			return SYMBOL_ERR_CANT_ACCESS_PDB_FILE;
		}

		m_Filesize = file_attr_data.nFileSizeLow;
	}

	m_hPdbFile = CreateFileW(m_szPdbPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, NULL, nullptr);
	if (m_hPdbFile == INVALID_HANDLE_VALUE)
	{
		LOG(1, "SYMBOL_LOADER: can't open PDB file: 0x%08X\n", GetLastError());

		return SYMBOL_ERR_CANT_OPEN_PDB_FILE;
	}

	if (pdb_path_out)
	{
		*pdb_path_out = m_szPdbPath;
	}

	m_bReady = true;

	return SYMBOL_ERR_SUCCESS;
}

void SYMBOL_LOADER::Cleanup()
{
	LOG(1, "SYMBOL_LOADER::Cleanup\n");

	m_bReady = false;

	if (m_hPdbFile)
	{
		CloseHandle(m_hPdbFile);

		m_hPdbFile = nullptr;
	}
}

void SYMBOL_LOADER::SetDownload(bool bDownload)
{
	m_bStartDownload = bDownload;
}

void SYMBOL_LOADER::Interrupt()
{
	LOG(1, "SYMBOL_LOADER::Interrupt\n");

	m_bInterruptEvent = true;

	if (m_hInterruptEvent)
	{
		if (!SetEvent(m_hInterruptEvent))
		{
			LOG(1, "SYMBOL_LOADER: SetEvent failed to trigger interrupt event: %08X\n", GetLastError());
		}
		else
		{
			LOG(1, "SYMBOL_LOADER: interrupt event set\n");
		}
	}
	else
	{
		LOG(1, "SYMBOL_LOADER: no interrupt event specified\n");
	}
}

const std::wstring & SYMBOL_LOADER::GetFilepath() const
{
	return m_szPdbPath;
}

DWORD SYMBOL_LOADER::GetFilesize() const
{
	return m_Filesize;
}

float SYMBOL_LOADER::GetDownloadProgress() const
{
	if (m_fProgress == 1.0f)
	{
		return m_fProgress;
	}

	return m_DlMgr.GetDownloadProgress();
}

bool SYMBOL_LOADER::IsReady() const
{
	return m_bReady;
}