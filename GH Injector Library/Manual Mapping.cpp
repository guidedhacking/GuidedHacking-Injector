#include "pch.h"

#include "Manual Mapping.h"
using namespace NATIVE;
using namespace MMAP_NATIVE;

DWORD __declspec(code_seg(".mmap_sec$1")) __stdcall ManualMapping_Shell(MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".mmap_sec$2")) ManualMapping_Shell_End();

DWORD MMAP_NATIVE::ManualMap(const wchar_t * szDllFile, HANDLE hTargetProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD Timeout, ERROR_DATA & error_data)
{
#if !defined(_WIN64) && defined (DUMP_SHELLCODE)
	auto length = ReCa<BYTE *>(ManualMapping_Shell_End) - ReCa<BYTE *>(ManualMapping_Shell);
	DumpShellcode(ReCa<BYTE *>(ManualMapping_Shell), length, L"ManualMapping_Shell_WOW64");
#endif

	LOG("Begin ManualMap\n");

	MANUAL_MAPPING_DATA data{ 0 };
	data.Flags = Flags;

	size_t len = 0;
	HRESULT hr = StringCbLengthW(szDllFile, sizeof(data.szPathBuffer), &len);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		return INJ_ERR_STRINGC_XXX_FAIL;
	}

	data.DllPath.Length = (WORD)len;
	data.DllPath.MaxLength = (WORD)sizeof(data.szPathBuffer);
	data.DllPath.szBuffer = data.szPathBuffer;

	hr = StringCbCopyW(data.szPathBuffer, sizeof(data.szPathBuffer), szDllFile);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		return INJ_ERR_STRINGC_XXX_FAIL;
	}

	const wchar_t * pDllName = wcsrchr(szDllFile, '\\') + 1;

	hr = StringCbLengthW(pDllName, sizeof(data.szNameBuffer), &len);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		return INJ_ERR_STRINGC_XXX_FAIL;
	}

	data.DllName.Length = (WORD)len;
	data.DllName.MaxLength = (WORD)sizeof(data.szNameBuffer);
	data.DllName.szBuffer = data.szNameBuffer;

	hr = StringCbCopyW(data.szNameBuffer, sizeof(data.szNameBuffer), pDllName);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		return INJ_ERR_STRINGC_XXX_FAIL;
	}

	ULONG_PTR ShellSize = (ULONG_PTR)ManualMapping_Shell_End - (ULONG_PTR)ManualMapping_Shell;
	auto AllocationSize = sizeof(MANUAL_MAPPING_DATA) + ShellSize + 0x10;
	BYTE * pAllocBase = ReCa<BYTE *>(VirtualAllocEx(hTargetProc, nullptr, AllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

	BYTE * pArg = pAllocBase;
	BYTE * pShell = ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pArg) + sizeof(MANUAL_MAPPING_DATA), 0x10));

	LOG("Shellsize = %IX bytes\n", ShellSize);
	LOG("pArg   = %p\npShell = %p\nAllocationSize = %08X\n", pArg, pShell, (DWORD)AllocationSize);

	if (!pArg)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		return INJ_ERR_OUT_OF_MEMORY_EXT;
	}

	if (!WriteProcessMemory(hTargetProc, pArg, &data, sizeof(MANUAL_MAPPING_DATA), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	if (!WriteProcessMemory(hTargetProc, pShell, ManualMapping_Shell, ShellSize, nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	LOG("Data written\n");
	LOG("NtSetInformationFile: %p\n", data.f.NtSetInformationFile);

	DWORD remote_ret = 0;
	DWORD dwRet = StartRoutine(hTargetProc, ReCa<f_Routine>(pShell), pArg, Method, (Flags & INJ_THREAD_CREATE_CLOAKED) != 0, remote_ret, Timeout, error_data);

	if (dwRet != SR_ERR_SUCCESS)
	{
		if (Method != LAUNCH_METHOD::LM_QueueUserAPC && !(Method == LAUNCH_METHOD::LM_HijackThread && dwRet == SR_HT_ERR_REMOTE_TIMEOUT))
		{
			VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);
		}

		return dwRet;
	}

	LOG("Fetching routine data\n");

	if (!ReadProcessMemory(hTargetProc, pAllocBase, &data, sizeof(MANUAL_MAPPING_DATA), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		if (Method != LAUNCH_METHOD::LM_QueueUserAPC)
		{
			VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);
		}

		return INJ_ERR_VERIFY_RESULT_FAIL;
	}

	if (Method != LAUNCH_METHOD::LM_QueueUserAPC)
	{
		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);
	}

	if (remote_ret != INJ_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, (DWORD)data.ntRet);

		return remote_ret;
	}

	if (!data.hRet)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return INJ_ERR_FAILED_TO_LOAD_DLL;
	}

	hOut = data.hRet;

	LOG("End ManualMap\n");

	return INJ_ERR_SUCCESS;
}

template <class T>
__forceinline T * NewObject(MANUAL_MAPPING_FUNCTION_TABLE * f, size_t Count = 1)
{
	return ReCa<T *>(f->RtlAllocateHeap(f->pLdrpHeap, HEAP_ZERO_MEMORY, sizeof(T) * Count));
}

template <class T>
__forceinline void DeleteObject(MANUAL_MAPPING_FUNCTION_TABLE * f, T * Object)
{
	if (Object)
	{
		f->RtlFreeHeap(f->pLdrpHeap, NULL, Object);
	}
}

__forceinline WORD SizeAnsiString(const char * szString)
{
	const char * c = szString;
	while (*c)
	{
		c++;
	}

	return (WORD)(c - szString);
}

__forceinline bool InitAnsiString(MANUAL_MAPPING_FUNCTION_TABLE * f, ANSI_STRING * String, const char * szString)
{
	const char * c = szString;
	while (*c)
	{
		c++;
	}

	WORD Length = (WORD)(c - szString);
	if (!Length)
	{
		return false;
	}

	String->szBuffer = NewObject<char>(f, (((size_t)Length) + 1) / sizeof(char));
	if (!String->szBuffer)
	{
		return false;
	}

	String->Length = Length;
	String->MaxLength = Length + 1 * sizeof(char);
	f->memmove(String->szBuffer, szString, Length);

	return true;
}

DWORD __declspec(code_seg(".mmap_sec$1")) __stdcall ManualMapping_Shell(MANUAL_MAPPING_DATA * pData)
{
	if (!pData)
	{
		return INJ_MM_ERR_NO_DATA;
	}

	BYTE * pBase = nullptr;

	DWORD		Flags = pData->Flags;
	NTSTATUS	ntRet = STATUS_SUCCESS;
	HANDLE		hProc = MPTR(-1);

	IMAGE_DOS_HEADER * pDosHeader = nullptr;
	IMAGE_NT_HEADERS * pNtHeaders = nullptr;
	IMAGE_OPTIONAL_HEADER * pOptionalHeader = nullptr;
	IMAGE_FILE_HEADER * pFileHeader = nullptr;

	auto * f = &pData->f;
	f->pLdrpHeap = *f->LdrpHeap;

	if (!f->pLdrpHeap)
	{
		return INJ_MM_ERR_INVALID_HEAP_HANDLE;
	}

	//convert path to nt path
	UNICODE_STRING DllNtPath{ 0 };
	DllNtPath.Length = pData->DllPath.Length;
	DllNtPath.MaxLength = sizeof(wchar_t[MAX_PATH + 4]);
	DllNtPath.szBuffer = NewObject<wchar_t>(f, DllNtPath.MaxLength / sizeof(wchar_t));

	if (!DllNtPath.szBuffer)
	{
		return INJ_MM_ERR_HEAP_ALLOC;
	}

	//nt path prefix "\??\"
	f->memmove(DllNtPath.szBuffer + 0, pData->NtPathPrefix, sizeof(wchar_t[4]));
	f->memmove(DllNtPath.szBuffer + 4, pData->szPathBuffer, DllNtPath.Length);
	DllNtPath.Length += sizeof(wchar_t[4]);

	UNICODE_STRING DllName = pData->DllName;
	DllName.szBuffer = pData->szNameBuffer;

	UNICODE_STRING DllPath = pData->DllPath;
	DllPath.szBuffer = pData->szPathBuffer;

	auto * oa = NewObject<OBJECT_ATTRIBUTES>(f);
	InitializeObjectAttributes(oa, &DllNtPath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
	IO_STATUS_BLOCK io_status{ 0 };

	HANDLE hDllFile = nullptr;

	ntRet = f->NtOpenFile(&hDllFile, FILE_GENERIC_READ, oa, &io_status, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

	DeleteObject(f, oa);
	DeleteObject(f, DllNtPath.szBuffer);

	if (NT_FAIL(ntRet))
	{
		pData->ntRet = ntRet;

		return INJ_MM_ERR_NT_OPEN_FILE;
	}

	BYTE * Headers = NewObject<BYTE>(f, 0x1000);
	if (!Headers)
	{
		f->NtClose(hDllFile);

		return INJ_MM_ERR_HEAP_ALLOC;
	}

	ntRet = f->NtReadFile(hDllFile, nullptr, nullptr, nullptr, &io_status, Headers, 0x1000, nullptr, nullptr);
	if (NT_FAIL(ntRet))
	{
		pData->ntRet = ntRet;

		DeleteObject(f, Headers);

		f->NtClose(hDllFile);

		return INJ_MM_ERR_NT_READ_FILE;
	}

	pDosHeader = ReCa<IMAGE_DOS_HEADER *>(Headers);
	pNtHeaders = ReCa<IMAGE_NT_HEADERS *>(Headers + pDosHeader->e_lfanew);
	LARGE_INTEGER ImageSize{ pNtHeaders->OptionalHeader.SizeOfImage };

	DeleteObject(f, Headers);

	auto * fsi = NewObject<FILE_STANDARD_INFO>(f);
	ntRet = f->NtQueryInformationFile(hDllFile, &io_status, fsi, sizeof(FILE_STANDARD_INFO), FILE_INFORMATION_CLASS::FileStandardInformation);
	if (NT_FAIL(ntRet))
	{
		pData->ntRet = ntRet;

		DeleteObject(f, fsi);

		f->NtClose(hDllFile);

		return INJ_MM_ERR_CANT_GET_FILE_SIZE;
	}

	BYTE * pRawData = nullptr;
	SIZE_T RawSize = fsi->AllocationSize.LowPart;

	ntRet = f->NtAllocateVirtualMemory(hProc, ReCa<void **>(&pRawData), 0, &RawSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (NT_FAIL(ntRet))
	{
		pData->ntRet = ntRet;

		DeleteObject(f, fsi);

		f->NtClose(hDllFile);

		return INJ_MM_ERR_MEMORY_ALLOCATION_FAILED;
	}

	FILE_POSITION_INFORMATION pos{ 0 };
	ntRet = f->NtSetInformationFile(hDllFile, &io_status, &pos, sizeof(pos), FILE_INFORMATION_CLASS::FilePositionInformation);
	if (NT_FAIL(ntRet))
	{
		pData->ntRet = ntRet;

		DeleteObject(f, fsi);

		RawSize = 0;
		f->NtFreeVirtualMemory(hProc, ReCa<void **>(&pRawData), &RawSize, MEM_RELEASE);
		f->NtClose(hDllFile);

		return INJ_MM_ERR_SET_FILE_POSITION;
	}

	ntRet = f->NtReadFile(hDllFile, nullptr, nullptr, nullptr, &io_status, pRawData, fsi->AllocationSize.LowPart, nullptr, nullptr);
	if (NT_FAIL(ntRet))
	{
		pData->ntRet = ntRet;

		DeleteObject(f, fsi);

		RawSize = 0;
		f->NtFreeVirtualMemory(hProc, ReCa<void **>(&pRawData), &RawSize, MEM_RELEASE);
		f->NtClose(hDllFile);

		return INJ_MM_ERR_NT_READ_FILE;
	}

	DeleteObject(f, fsi);

	pDosHeader = ReCa<IMAGE_DOS_HEADER *>(pRawData);
	pNtHeaders = ReCa<IMAGE_NT_HEADERS *>(pRawData + pDosHeader->e_lfanew);
	pOptionalHeader = &pNtHeaders->OptionalHeader;
	pFileHeader = &pNtHeaders->FileHeader;

	SIZE_T ImgSize = (SIZE_T)pOptionalHeader->SizeOfImage;
	ntRet = f->NtAllocateVirtualMemory(hProc, ReCa<void **>(&pBase), 0, &ImgSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (NT_FAIL(ntRet))
	{
		pData->ntRet = ntRet;

		RawSize = 0;
		f->NtFreeVirtualMemory(hProc, ReCa<void **>(&pRawData), &RawSize, MEM_RELEASE);
		f->NtClose(hDllFile);

		return INJ_MM_ERR_MEMORY_ALLOCATION_FAILED;
	}

	//copy header and sections
	f->memmove(pBase, pRawData, pOptionalHeader->SizeOfHeaders);

	auto * pCurrentSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
	for (UINT i = 0; i != pFileHeader->NumberOfSections; ++i, ++pCurrentSectionHeader)
	{
		if (pCurrentSectionHeader->SizeOfRawData)
		{
			f->memmove(pBase + pCurrentSectionHeader->VirtualAddress, pRawData + pCurrentSectionHeader->PointerToRawData, pCurrentSectionHeader->SizeOfRawData);
		}
	}

	pDosHeader = ReCa<IMAGE_DOS_HEADER *>(pBase);
	pNtHeaders = ReCa<IMAGE_NT_HEADERS *>(pBase + pDosHeader->e_lfanew);
	pOptionalHeader = &pNtHeaders->OptionalHeader;
	pFileHeader = &pNtHeaders->FileHeader;

	RawSize = 0;
	f->NtFreeVirtualMemory(hProc, ReCa<void **>(&pRawData), &RawSize, MEM_RELEASE);

	//relocate image

	BYTE * LocationDelta = pBase - pOptionalHeader->ImageBase;

	if (LocationDelta)
	{
		auto * pRelocDir = ReCa<IMAGE_DATA_DIRECTORY *>(&pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

		if (!pRelocDir->Size)
		{
			ImgSize = 0;
			f->NtFreeVirtualMemory(hProc, ReCa<void **>(&pBase), &ImgSize, MEM_RELEASE);
			f->NtClose(hDllFile);

			return INJ_MM_ERR_IMAGE_CANT_BE_RELOCATED;
		}

		auto * pRelocData = ReCa<IMAGE_BASE_RELOCATION *>(pBase + pRelocDir->VirtualAddress);

		while (pRelocData->VirtualAddress)
		{
			WORD * pRelativeInfo = ReCa<WORD *>(pRelocData + 1);
			UINT RelocCount = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			for (UINT i = 0; i < RelocCount; ++i, ++pRelativeInfo)
			{
				if (RELOC_FLAG(*pRelativeInfo))
				{
					ULONG_PTR * pPatch = ReCa<ULONG_PTR *>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
					*pPatch += ReCa<ULONG_PTR>(LocationDelta);
				}
			}

			pRelocData = ReCa<IMAGE_BASE_RELOCATION *>(ReCa<BYTE *>(pRelocData) + pRelocData->SizeOfBlock);

			if (pRelocData >= reinterpret_cast<IMAGE_BASE_RELOCATION *>(pBase + pRelocDir->VirtualAddress + pRelocDir->Size))
			{
				break;
			}
		}

		pOptionalHeader->ImageBase += ReCa<ULONG_PTR>(LocationDelta);
	}

	if ((Flags & (INJ_MM_RESOLVE_IMPORTS | INJ_MM_RUN_DLL_MAIN)) && pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		bool ErrorBreak = false;

		auto * pImportDescr = ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name)
		{
			char * szMod = ReCa<char *>(pBase + pImportDescr->Name);
			ANSI_STRING ModNameA{ 0 };
			if (!InitAnsiString(f, &ModNameA, szMod))
			{
				ntRet = STATUS_HEAP_CORRUPTION;

				ErrorBreak = true;
				break;
			}

			HINSTANCE hDll = NULL;
			LDRP_LOAD_CONTEXT_FLAGS flags{ 0 };

			UNICODE_STRING ModNameW{ 0 };
			ModNameW.szBuffer = NewObject<wchar_t>(f, MAX_PATH);
			ModNameW.MaxLength = sizeof(wchar_t[MAX_PATH]);

			ntRet = f->RtlAnsiStringToUnicodeString(&ModNameW, &ModNameA, FALSE);
			if (NT_FAIL(ntRet))
			{
				DeleteObject(f, ModNameW.szBuffer);

				ErrorBreak = true;
				break;
			}

			LDRP_UNICODE_STRING_BUNDLE * pModPathW = NewObject<LDRP_UNICODE_STRING_BUNDLE>(f, 1);

			pModPathW->String.MaxLength = sizeof(pModPathW->StaticBuffer);
			pModPathW->String.szBuffer = pModPathW->StaticBuffer;

			ntRet = f->LdrpPreprocessDllName(&ModNameW, pModPathW, nullptr, &flags);

			DeleteObject(f, ModNameW.szBuffer);

			if (NT_FAIL(ntRet))
			{
				DeleteObject(f, pModPathW);

				ErrorBreak = true;
				break;
			}

			ntRet = f->LdrGetDllHandleEx(NULL, nullptr, nullptr, &pModPathW->String, ReCa<void **>(&hDll));

			if (NT_FAIL(ntRet))
			{
				auto * ctx = NewObject<LDRP_PATH_SEARCH_CONTEXT>(f);
				ctx->OriginalFullDllName = pModPathW->String.szBuffer;
				LDR_DATA_TABLE_ENTRY * entry_out = nullptr;

				ntRet = f->LdrpLoadDll(&pModPathW->String, ctx, { 0 }, &entry_out);

				if (NT_SUCCESS(ntRet))
				{
					hDll = ReCa<HINSTANCE>(entry_out->DllBase);
				}

				DeleteObject(f, ctx);
			}

			DeleteObject(f, pModPathW);

			if (NT_FAIL(ntRet))
			{
				ErrorBreak = true;
				break;
			}

			IMAGE_THUNK_DATA * pThunk = ReCa<IMAGE_THUNK_DATA *>(pBase + pImportDescr->OriginalFirstThunk);
			IMAGE_THUNK_DATA * pIAT = ReCa<IMAGE_THUNK_DATA *>(pBase + pImportDescr->FirstThunk);

			if (!pImportDescr->OriginalFirstThunk)
			{
				pThunk = pIAT;
			}

			for (; pThunk->u1.AddressOfData; ++pThunk, ++pIAT)
			{
				UINT_PTR * pFuncRef = ReCa<UINT_PTR *>(pIAT);

				IMAGE_IMPORT_BY_NAME * pImport;
				if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal))
				{
					ntRet = f->LdrGetProcedureAddress(ReCa<void *>(hDll), nullptr, IMAGE_ORDINAL(pThunk->u1.Ordinal), ReCa<void **>(pFuncRef));
				}
				else
				{
					pImport = ReCa<IMAGE_IMPORT_BY_NAME *>(pBase + (pThunk->u1.AddressOfData));
					ANSI_STRING import{ 0 };
					import.szBuffer		= pImport->Name;
					import.Length = SizeAnsiString(import.szBuffer);
					import.MaxLength = import.Length + 1 * sizeof(char);

					ntRet = f->LdrGetProcedureAddress(ReCa<void *>(hDll), &import, IMAGE_ORDINAL(pThunk->u1.Ordinal), ReCa<void **>(pFuncRef));
				}

				if (NT_FAIL(ntRet))
				{
					ErrorBreak = true;
					break;
				}
			}

			if (ErrorBreak)
			{
				break;
			}

			++pImportDescr;
		}

		if (ErrorBreak)
		{
			pData->ntRet = ntRet;

			f->NtClose(hDllFile);

			return INJ_MM_ERR_IMPORT_FAIL;
		}
	}

	if ((Flags & INJ_MM_RESOLVE_DELAY_IMPORTS) && pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size)
	{
		bool ErrorBreak = false;

		auto * pDelayImportDescr = ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);
		while (pDelayImportDescr->DllNameRVA)
		{
			char * szMod = ReCa<char *>(pBase + pDelayImportDescr->DllNameRVA);
			ANSI_STRING ModNameA{ 0 };
			if (!InitAnsiString(f, &ModNameA, szMod))
			{
				ntRet = STATUS_HEAP_CORRUPTION;

				ErrorBreak = true;
				break;
			}

			HINSTANCE hDll = NULL;
			LDRP_LOAD_CONTEXT_FLAGS flags{ 0 };

			UNICODE_STRING ModNameW{ 0 };
			ModNameW.szBuffer = NewObject<wchar_t>(f, MAX_PATH);
			ModNameW.MaxLength = sizeof(wchar_t[MAX_PATH]);

			ntRet = f->RtlAnsiStringToUnicodeString(&ModNameW, &ModNameA, FALSE);
			if (NT_FAIL(ntRet))
			{
				DeleteObject(f, ModNameW.szBuffer);

				ErrorBreak = true;
				break;
			}

			auto * pModPathW = NewObject<LDRP_UNICODE_STRING_BUNDLE>(f, 1);

			pModPathW->String.MaxLength = sizeof(pModPathW->StaticBuffer);
			pModPathW->String.szBuffer = pModPathW->StaticBuffer;

			ntRet = f->LdrpPreprocessDllName(&ModNameW, pModPathW, nullptr, &flags);

			DeleteObject(f, ModNameW.szBuffer);

			if (NT_FAIL(ntRet))
			{
				DeleteObject(f, pModPathW);

				ErrorBreak = true;
				break;
			}

			ntRet = f->LdrGetDllHandleEx(NULL, nullptr, nullptr, &pModPathW->String, ReCa<void **>(&hDll));

			if (NT_FAIL(ntRet))
			{
				auto * ctx = NewObject<LDRP_PATH_SEARCH_CONTEXT>(f);
				ctx->OriginalFullDllName = pModPathW->String.szBuffer;
				LDR_DATA_TABLE_ENTRY * entry_out = nullptr;

				ntRet = f->LdrpLoadDll(&pModPathW->String, ctx, { 0 }, &entry_out);

				if (NT_SUCCESS(ntRet))
				{
					hDll = ReCa<HINSTANCE>(entry_out->DllBase);
				}

				DeleteObject(f, ctx);
			}

			DeleteObject(f, pModPathW);

			if (NT_FAIL(ntRet))
			{
				ErrorBreak = true;
				break;
			}

			if (pDelayImportDescr->ModuleHandleRVA)
			{
				HINSTANCE * pModule = ReCa<HINSTANCE *>(pBase + pDelayImportDescr->ModuleHandleRVA);
				*pModule = hDll;
			}

			IMAGE_THUNK_DATA * pIAT = ReCa<IMAGE_THUNK_DATA *>(pBase + pDelayImportDescr->ImportAddressTableRVA);
			IMAGE_THUNK_DATA * pNameTable = ReCa<IMAGE_THUNK_DATA *>(pBase + pDelayImportDescr->ImportNameTableRVA);

			for (; pIAT->u1.Function; ++pIAT, ++pNameTable)
			{
				UINT_PTR pFunc = 0;
				if (IMAGE_SNAP_BY_ORDINAL(pNameTable->u1.Ordinal))
				{
					f->LdrGetProcedureAddress(ReCa<void *>(hDll), nullptr, IMAGE_ORDINAL(pNameTable->u1.Ordinal), ReCa<void **>(&pFunc));
				}
				else
				{
					auto pImport = ReCa<IMAGE_IMPORT_BY_NAME *>(pBase + (pNameTable->u1.AddressOfData));
					ANSI_STRING import{ 0 };
					import.szBuffer		= pImport->Name;
					import.Length = SizeAnsiString(import.szBuffer);
					import.MaxLength = import.Length + 1 * sizeof(char);

					f->LdrGetProcedureAddress(ReCa<void *>(hDll), &import, IMAGE_ORDINAL(pNameTable->u1.Ordinal), ReCa<void **>(&pFunc));
				}

				if (NT_FAIL(ntRet))
				{
					ErrorBreak = true;
					break;
				}
			}

			++pDelayImportDescr;
		}

		if (ErrorBreak)
		{
			pData->ntRet = ntRet;

			f->NtClose(hDllFile);

			return INJ_MM_ERR_DELAY_IMPORT_FAIL;
		}
	}

	if (Flags & INJ_MM_INIT_SECURITY_COOKIE && pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size)
	{
#ifdef _WIN64
		ULONGLONG new_cookie = ((UINT_PTR)pBase) & 0x0000FFFFFFFFFFFF;
		if (new_cookie == 0x2B992DDFA232)
		{
			++new_cookie;
		}
		else if (!(new_cookie & 0x0000FFFF00000000))
		{
			new_cookie |= (new_cookie | 0x4711) << 0x10;
		}
#else
		DWORD new_cookie = (UINT_PTR)pBase;
		if (new_cookie == 0xBB40E64E)
		{
			++new_cookie;
		}
		else if (!(new_cookie & 0xFFFF0000))
		{
			new_cookie |= (new_cookie | 0x4711) << 16;
		}
#endif
		auto pLoadConfigData = ReCa<IMAGE_LOAD_CONFIG_DIRECTORY *>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
		pLoadConfigData->SecurityCookie = new_cookie;
	}

	if (Flags & INJ_MM_ENABLE_EXCEPTIONS)
	{
		ntRet = f->RtlInsertInvertedFunctionTable(pBase, pOptionalHeader->SizeOfImage);
		if (NT_FAIL(ntRet))
		{
			pData->ntRet = ntRet;

			f->NtClose(hDllFile);

			return INJ_MM_ERR_ENABLING_SEH_FAILED;
		}
	}

	if (Flags & INJ_MM_SET_PAGE_PROTECTIONS)
	{
		ULONG OldProtection = 0;
		SIZE_T SizeOut = pOptionalHeader->SizeOfHeaders;
		ntRet = f->NtProtectVirtualMemory(hProc, ReCa<void **>(&pBase), &SizeOut, PAGE_EXECUTE_READ, &OldProtection);

		if (NT_SUCCESS(ntRet))
		{
			pCurrentSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
			for (UINT i = 0; i != pFileHeader->NumberOfSections; ++i, ++pCurrentSectionHeader)
			{
				void * pSectionBase = pBase + pCurrentSectionHeader->VirtualAddress;
				DWORD characteristics = pCurrentSectionHeader->Characteristics;
				SIZE_T SectionSize = pCurrentSectionHeader->SizeOfRawData;

				if (SectionSize)
				{
					ULONG NewProtection = PAGE_NOACCESS;

					if (characteristics & IMAGE_SCN_MEM_EXECUTE)
					{
						if (characteristics & IMAGE_SCN_MEM_WRITE)
						{
							NewProtection = PAGE_EXECUTE_READWRITE;
						}
						else if (characteristics & IMAGE_SCN_MEM_READ)
						{
							NewProtection = PAGE_EXECUTE_READ;
						}
						else
						{
							NewProtection = PAGE_EXECUTE;
						}
					}
					else
					{
						if (characteristics & IMAGE_SCN_MEM_WRITE)
						{
							NewProtection = PAGE_READWRITE;
						}
						else if (characteristics & IMAGE_SCN_MEM_READ)
						{
							NewProtection = PAGE_READONLY;
						}
					}

					ntRet = f->NtProtectVirtualMemory(hProc, &pSectionBase, &SectionSize, NewProtection, &OldProtection);
					if (NT_FAIL(ntRet))
					{
						break;
					}
				}
			}
		}

		if (NT_FAIL(ntRet))
		{
			pData->ntRet = ntRet;

			f->NtClose(hDllFile);

			return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
		}
	}

	if ((Flags & INJ_MM_EXECUTE_TLS) && pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		auto * pTLS = ReCa<IMAGE_TLS_DIRECTORY *>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		//LdrpHandleTlsData either crashes or returns STATUS_SUCCESS -> no point in error checking
		//It also only accesses the DllBase member of the ldr entry thus a dummy entry is sufficient

		auto * pDummyLdr = NewObject<LDR_DATA_TABLE_ENTRY>(f);
		pDummyLdr->DllBase = pBase;
		f->LdrpHandleTlsData(pDummyLdr);
		DeleteObject(f, pDummyLdr);

		auto * pCallback = ReCa<PIMAGE_TLS_CALLBACK *>(pTLS->AddressOfCallBacks);
		for (; pCallback && (*pCallback); ++pCallback)
		{
			auto Callback = *pCallback;
			Callback(pBase, DLL_PROCESS_ATTACH, nullptr);
		}
	}

	if (Flags & INJ_MM_RUN_DLL_MAIN && pOptionalHeader->AddressOfEntryPoint)
	{
		f_DLL_ENTRY_POINT DllMain = ReCa<f_DLL_ENTRY_POINT>(pBase + pOptionalHeader->AddressOfEntryPoint);
		DllMain(ReCa<HINSTANCE>(pBase), DLL_PROCESS_ATTACH, nullptr);
	}

	if (Flags & INJ_MM_CLEAN_DATA_DIR && !(Flags & INJ_MM_SET_PAGE_PROTECTIONS))
	{
		DWORD Size = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
		if (Size)
		{
			auto * pImportDescr = ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
			while (pImportDescr->Name)
			{
				char * szMod = ReCa<char *>(pBase + pImportDescr->Name);
				for (; *szMod++; *szMod = '\0');
				pImportDescr->Name = 0;

				IMAGE_THUNK_DATA * pThunk = ReCa<IMAGE_THUNK_DATA *>(pBase + pImportDescr->OriginalFirstThunk);
				IMAGE_THUNK_DATA * pIAT = ReCa<IMAGE_THUNK_DATA *>(pBase + pImportDescr->FirstThunk);

				if (!pImportDescr->OriginalFirstThunk)
				{
					pThunk = pIAT;
				}

				for (; pThunk->u1.AddressOfData; ++pThunk, ++pIAT)
				{
					if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal))
					{
						pThunk->u1.Ordinal = 0;
					}
					else
					{
						auto * pImport = ReCa<IMAGE_IMPORT_BY_NAME *>(pBase + (pThunk->u1.AddressOfData));
						char * szFunc = pImport->Name;
						for (; *szFunc++; *szFunc = '\0');
					}
				}

				pImportDescr->OriginalFirstThunk = 0;
				pImportDescr->FirstThunk = 0;

				++pImportDescr;
			}

			pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
			pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;
		}

		Size = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size;
		if (Size && !(Flags & INJ_MM_RESOLVE_DELAY_IMPORTS))
		{
			auto * pDelayImportDescr = ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);

			while (pDelayImportDescr->DllNameRVA)
			{
				char * szMod = ReCa<char *>(pBase + pDelayImportDescr->DllNameRVA);
				for (; *szMod++; *szMod = '\0');
				pDelayImportDescr->DllNameRVA = 0;

				pDelayImportDescr->ModuleHandleRVA = 0;

				IMAGE_THUNK_DATA * pIAT = ReCa<IMAGE_THUNK_DATA *>(pBase + pDelayImportDescr->ImportAddressTableRVA);
				IMAGE_THUNK_DATA * pNameTable = ReCa<IMAGE_THUNK_DATA *>(pBase + pDelayImportDescr->ImportNameTableRVA);

				for (; pIAT->u1.Function; ++pIAT, ++pNameTable)
				{

					if (IMAGE_SNAP_BY_ORDINAL(pNameTable->u1.Ordinal))
					{
						pNameTable->u1.Ordinal = 0;
					}
					else
					{
						auto * pImport = ReCa<IMAGE_IMPORT_BY_NAME *>(pBase + (pNameTable->u1.AddressOfData));
						char * szFunc = pImport->Name;
						for (; (*szFunc)++; *szFunc = '\0');
					}
				}

				pDelayImportDescr->ImportAddressTableRVA = 0;
				pDelayImportDescr->ImportNameTableRVA = 0;

				++pDelayImportDescr;
			}

			pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress = 0;
			pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size = 0;
		}

		Size = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
		if (Size)
		{
			auto * pDebugDir = ReCa<IMAGE_DEBUG_DIRECTORY *>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);

			BYTE * pDebugData = pBase + pDebugDir->AddressOfRawData;
			f->RtlZeroMemory(pDebugData, pDebugDir->SizeOfData);

			pDebugDir->SizeOfData = 0;
			pDebugDir->AddressOfRawData = 0;
			pDebugDir->PointerToRawData = 0;

			pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
			pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
		}

		Size = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
		if (Size)
		{
			auto * pRelocData = ReCa<IMAGE_BASE_RELOCATION *>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			while (pRelocData->VirtualAddress)
			{
				WORD * pRelativeInfo = ReCa<WORD *>(pRelocData + 1);
				UINT RelocCount = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION));

				f->RtlZeroMemory(pRelativeInfo, RelocCount);

				pRelocData = ReCa<IMAGE_BASE_RELOCATION *>(ReCa<BYTE *>(pRelocData) + pRelocData->SizeOfBlock);
			}

			pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
			pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
		}

		Size = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
		if (Size)
		{
			auto * pTLS = ReCa<IMAGE_TLS_DIRECTORY *>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
			auto * pCallback = ReCa<PIMAGE_TLS_CALLBACK *>(pTLS->AddressOfCallBacks);
			for (; pCallback && (*pCallback); ++pCallback)
			{
				*pCallback = nullptr;
			}

			pTLS->AddressOfCallBacks = 0;
			pTLS->AddressOfIndex = 0;
			pTLS->EndAddressOfRawData = 0;
			pTLS->SizeOfZeroFill = 0;
			pTLS->StartAddressOfRawData = 0;

			pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0;
			pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = 0;
		}
	}

	if (Flags & (INJ_ERASE_HEADER | INJ_FAKE_HEADER))
	{
		void * base = pBase;
		SIZE_T header_size = pOptionalHeader->SizeOfHeaders;
		ULONG old_access = NULL;

		if (Flags & INJ_MM_SET_PAGE_PROTECTIONS)
		{
			ntRet = f->NtProtectVirtualMemory(hProc, &base, &header_size, PAGE_EXECUTE_READWRITE, &old_access);

			if (NT_FAIL(ntRet))
			{
				pData->ntRet = ntRet;

				f->NtClose(hDllFile);

				return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
			}
		}

		if (Flags & INJ_ERASE_HEADER)
		{
			f->RtlZeroMemory(pBase, header_size);
		}
		else if (Flags & INJ_FAKE_HEADER)
		{
			PEB * pPEB = nullptr;

#ifdef  _WIN64
			pPEB = ReCa<PEB *>(__readgsqword(0x60));
#else
			pPEB = ReCa<PEB *>(__readfsdword(0x30));
#endif 
			if (!pPEB)
			{
				f->NtClose(hDllFile);

				return INJ_MM_ERR_CANT_GET_PEB;
			}

			if (!pPEB->Ldr || !pPEB->Ldr->InLoadOrderModuleListHead.Flink || !pPEB->Ldr->InLoadOrderModuleListHead.Flink->Flink)
			{
				f->NtClose(hDllFile);

				return INJ_MM_ERR_INVALID_PEB_DATA;
			}

			auto * ntdll_ldr = ReCa<LDR_DATA_TABLE_ENTRY *>(pPEB->Ldr->InLoadOrderModuleListHead.Flink->Flink);
			if (!ntdll_ldr || !ntdll_ldr->DllBase)
			{
				f->NtClose(hDllFile);

				return INJ_MM_ERR_INVALID_PEB_DATA;
			}

			BYTE * p_ntdll = ReCa<BYTE *>(ntdll_ldr->DllBase);
			IMAGE_DOS_HEADER * p_nt_dos	= ReCa<IMAGE_DOS_HEADER *>(p_ntdll);
			IMAGE_NT_HEADERS * p_nt_nt	= ReCa<IMAGE_NT_HEADERS *>(p_ntdll + p_nt_dos->e_lfanew);

			f->RtlZeroMemory(pBase, header_size);

			f->memmove(pBase, ntdll_ldr->DllBase, min(p_nt_nt->OptionalHeader.SizeOfHeaders, header_size));
		}

		if (Flags & INJ_MM_SET_PAGE_PROTECTIONS)
		{
			ntRet = f->NtProtectVirtualMemory(hProc, &base, &header_size, old_access, &old_access);

			if (NT_FAIL(ntRet))
			{
				pData->ntRet = ntRet;

				f->NtClose(hDllFile);

				return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
			}
		}
	}

	f->NtClose(hDllFile);

	pData->hRet = ReCa<HINSTANCE>(pBase);

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$2")) ManualMapping_Shell_End()
{
	return 1;
}

MANUAL_MAPPING_FUNCTION_TABLE::MANUAL_MAPPING_FUNCTION_TABLE()
{
	NT_FUNC_CONSTRUCTOR_INIT(NtOpenFile);
	NT_FUNC_CONSTRUCTOR_INIT(NtReadFile);
	NT_FUNC_CONSTRUCTOR_INIT(NtClose);

	NT_FUNC_CONSTRUCTOR_INIT(NtSetInformationFile);
	NT_FUNC_CONSTRUCTOR_INIT(NtQueryInformationFile);

	NT_FUNC_CONSTRUCTOR_INIT(NtAllocateVirtualMemory);
	NT_FUNC_CONSTRUCTOR_INIT(NtProtectVirtualMemory);
	NT_FUNC_CONSTRUCTOR_INIT(NtFreeVirtualMemory);

	NT_FUNC_CONSTRUCTOR_INIT(memmove);
	NT_FUNC_CONSTRUCTOR_INIT(RtlZeroMemory);
	NT_FUNC_CONSTRUCTOR_INIT(RtlAllocateHeap);
	NT_FUNC_CONSTRUCTOR_INIT(RtlFreeHeap);

	NT_FUNC_CONSTRUCTOR_INIT(LdrGetDllHandleEx);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpLoadDll);
	NT_FUNC_CONSTRUCTOR_INIT(LdrGetProcedureAddress);

	NT_FUNC_CONSTRUCTOR_INIT(RtlAnsiStringToUnicodeString);

	NT_FUNC_CONSTRUCTOR_INIT(LdrpPreprocessDllName);
	NT_FUNC_CONSTRUCTOR_INIT(RtlInsertInvertedFunctionTable);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpHandleTlsData);

	NT_FUNC_CONSTRUCTOR_INIT(LdrpModuleBaseAddressIndex);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpMappingInfoIndex);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpHeap);

	pLdrpHeap = nullptr;
}