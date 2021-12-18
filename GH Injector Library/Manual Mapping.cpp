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

	length = ReCa<BYTE *>(VectoredHandlerShell_End) - ReCa<BYTE *>(VectoredHandlerShell);
	DumpShellcode(ReCa<BYTE *>(VectoredHandlerShell), length, L"VectoredHandlerShell_WOW64");
#endif

	LOG(1, "Begin ManualMap\n");

	MANUAL_MAPPING_DATA data{ 0 };
	data.Flags			= Flags;
	data.OSVersion		= GetOSVersion();
	data.OSBuildNumber	= GetOSBuildVersion();

	size_t len = 0;
	HRESULT hr = StringCbLengthW(szDllFile, sizeof(data.szPathBuffer), &len);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		LOG(1, "StringCbLengthW failed: %08X\n", hr);

		return INJ_ERR_STRINGC_XXX_FAIL;
	}

	data.DllPath.Length		= (WORD)len;
	data.DllPath.MaxLength	= (WORD)sizeof(data.szPathBuffer);
	data.DllPath.szBuffer	= data.szPathBuffer;

	hr = StringCbCopyW(data.szPathBuffer, sizeof(data.szPathBuffer), szDllFile);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		LOG(1, "StringCbCopyW failed: %08X\n", hr);

		return INJ_ERR_STRINGC_XXX_FAIL;
	}

	const wchar_t * pDllName = wcsrchr(szDllFile, '\\');
	if (!pDllName)
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		LOG(1, "wcsrchr failed\n");

		return INJ_ERR_INVALID_PATH_SEPERATOR;
	}
	else
	{
		++pDllName;
	}

	hr = StringCbLengthW(pDllName, sizeof(data.szNameBuffer), &len);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		LOG(1, "StringCbLengthW failed: %08X\n", hr);

		return INJ_ERR_STRINGC_XXX_FAIL;
	}

	data.DllName.Length		= (WORD)len;
	data.DllName.MaxLength	= (WORD)sizeof(data.szNameBuffer);
	data.DllName.szBuffer	= data.szNameBuffer;

	hr = StringCbCopyW(data.szNameBuffer, sizeof(data.szNameBuffer), pDllName);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		LOG(1, "StringCbCopyW failed: %08X\n", hr);

		return INJ_ERR_STRINGC_XXX_FAIL;
	}

	LOG(1, "Shell data initialized\n");

	if (Flags & INJ_MM_SHIFT_MODULE_BASE && !(Flags & INJ_MM_SET_PAGE_PROTECTIONS))
	{
		auto seed = GetTickCount();
		std::mt19937 gen(seed);
		std::uniform_int_distribution<WORD> dis(MIN_SHIFT_OFFSET, MAX_SHIFT_OFFSET);

		WORD shift_offset = dis(gen);
		shift_offset = ALIGN_UP(shift_offset, BASE_ALIGNMENT);

		data.ShiftOffset = shift_offset;

		LOG(1, "Shift offset = %04X\n", shift_offset);
	}

	ULONG_PTR ShellSize		= ReCa<ULONG_PTR>(ManualMapping_Shell_End)	- ReCa<ULONG_PTR>(ManualMapping_Shell);
	ULONG_PTR VEHShellSize	= ReCa<ULONG_PTR>(VectoredHandlerShell_End) - ReCa<ULONG_PTR>(VectoredHandlerShell);

	if (!(Flags & INJ_MM_ENABLE_EXCEPTIONS))
	{
		VEHShellSize = 0;
	}

	auto AllocationSize = sizeof(MANUAL_MAPPING_DATA) + ShellSize + VEHShellSize + BASE_ALIGNMENT * 2;
	BYTE * pAllocBase	= ReCa<BYTE *>(VirtualAllocEx(hTargetProc, nullptr, AllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

	BYTE * pArg			= pAllocBase;
	BYTE * pShell		= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pArg) + sizeof(MANUAL_MAPPING_DATA), BASE_ALIGNMENT));
	BYTE * pVEHShell	= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pShell) + ShellSize, BASE_ALIGNMENT));

	if (VEHShellSize)
	{
		data.pVEHShell		= pVEHShell;
		data.VEHShellSize	= MDWD(VEHShellSize);
	}

	if (!pArg)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "VirtualAllocEx failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_OUT_OF_MEMORY_EXT;
	}

	LOG(2, "Shellsize  = %08X\n", MDWD(ShellSize));
	LOG(2, "Total size = %08X\n", MDWD(AllocationSize));
	LOG(2, "pArg       = %p\n", pArg);
	LOG(2, "pShell     = %p\n", pShell);

	if (VEHShellSize)
	{
		LOG(2, "pVEHShell   = %p\n", pVEHShell);
	}

	if (!WriteProcessMemory(hTargetProc, pArg, &data, sizeof(MANUAL_MAPPING_DATA), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	LOG(1, "Shelldata written to memory\n");

	if (!WriteProcessMemory(hTargetProc, pShell, ManualMapping_Shell, ShellSize, nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	LOG(1, "Shell written to memory\n");

	if (VEHShellSize)
	{
		if (!WriteProcessMemory(hTargetProc, pVEHShell, VectoredHandlerShell, VEHShellSize, nullptr))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(1, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

			VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

			return INJ_ERR_WPM_FAIL;
		}

		LOG(1, "VEHShell written to memory\n");
	}

	if (Flags & INJ_THREAD_CREATE_CLOAKED)
	{
		Flags |= (INJ_CTF_FAKE_START_ADDRESS | INJ_CTF_HIDE_FROM_DEBUGGER);
	}

	LOG(1, "Entering StartRoutine\n");

	DWORD remote_ret = 0;
	DWORD dwRet = StartRoutine(hTargetProc, ReCa<f_Routine>(pShell), pArg, Method, Flags, remote_ret, Timeout, error_data);

	LOG(1, "Return from StartRoutine\n");

	if (dwRet != SR_ERR_SUCCESS)
	{
		LOG(1, "StartRoutine failed: %08X\n", dwRet);

		if (Method != LAUNCH_METHOD::LM_QueueUserAPC && !(Method == LAUNCH_METHOD::LM_HijackThread && dwRet == SR_HT_ERR_REMOTE_TIMEOUT))
		{
			VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);
		}

		return dwRet;
	}

	LOG(1, "Fetching routine data\n");

	if (!ReadProcessMemory(hTargetProc, pAllocBase, &data, sizeof(MANUAL_MAPPING_DATA), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "ReadProcessMemory failed: %08X\n", error_data.AdvErrorCode);

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

		LOG(1, "Shell failed: %08X\n", remote_ret);

		return remote_ret;
	}

	if (!data.hRet)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "Shell failed\n");

		return INJ_ERR_FAILED_TO_LOAD_DLL;
	}

	LOG(1, "Shell returned successfully\n");

	hOut = data.hRet;

	LOG(1, "Imagebase = %p\n", ReCa<void *>(hOut));

	return INJ_ERR_SUCCESS;
}

__forceinline UINT_PTR bit_rotate_r(UINT_PTR val, int count)
{
	return (val >> count) | (val << (-count));
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

	String->Length		= Length;
	String->MaxLength	= Length + 1 * sizeof(char);
	f->memmove(String->szBuffer, szString, Length);

	return true;
}

__forceinline void BuildDependencyRecord(MANUAL_MAPPING_FUNCTION_TABLE * f, MM_DEPENDENCY_RECORD ** head, HANDLE DllHandle)
{
	if (!head)
	{ 
		return;
	}

	//create new list (head)
	if (!(*head))
	{
		*head = NewObject<MM_DEPENDENCY_RECORD>(f);

		if (!(*head))
		{
			return;
		}

		(*head)->Next = *head;
		(*head)->Prev = *head;
		(*head)->DllHandle = DllHandle;

		return;
	}

	//create new entry
	auto next = NewObject<MM_DEPENDENCY_RECORD>(f);
	if (next)
	{
		(*head)->Prev->Next	= next;
		next->Prev			= (*head)->Prev;

		(*head)->Prev		= next;
		next->Next			= (*head);

		next->DllHandle = DllHandle;
	}
}

__forceinline NTSTATUS LoadModule(MANUAL_MAPPING_DATA * pData, MANUAL_MAPPING_FUNCTION_TABLE * f, char * szModule, HINSTANCE * hModule, MM_DEPENDENCY_RECORD ** head)
{
	//load module using LdrpLoadDll(Internal)
	//function protoype is heavily platform dependent

	LDR_DATA_TABLE_ENTRY * entry_out = nullptr;
	NTSTATUS ntRet = STATUS_SUCCESS;

	//create ANSI_STRING
	auto * ModNameA = NewObject<ANSI_STRING>(f);
	if (!ModNameA)
	{
		ntRet = INJ_MM_ERR_HEAP_ALLOC;

		return ntRet;
	}

	//move szModule into ANSI_STRING
	if (!InitAnsiString(f, ModNameA, szModule))
	{
		ntRet = STATUS_HEAP_CORRUPTION;

		DeleteObject(f, ModNameA);

		return ntRet;
	}

	//create UNICODE_STRING
	auto * ModNameW = NewObject<UNICODE_STRING>(f);
	if (!ModNameW)
	{
		ntRet = INJ_MM_ERR_HEAP_ALLOC;

		DeleteObject(f, ModNameA->szBuffer);
		DeleteObject(f, ModNameA);

		return ntRet;
	}

	//allocate buffer for UNICODE_STRING
	ModNameW->szBuffer	= NewObject<wchar_t>(f, MAX_PATH);
	ModNameW->MaxLength = sizeof(wchar_t[MAX_PATH]);

	if (!ModNameW->szBuffer)
	{
		ntRet = INJ_MM_ERR_HEAP_ALLOC;

		DeleteObject(f, ModNameW);

		DeleteObject(f, ModNameA->szBuffer);
		DeleteObject(f, ModNameA);

		return ntRet;
	}

	//convert dll name from ansi to unicode
	ntRet = f->RtlAnsiStringToUnicodeString(ModNameW, ModNameA, FALSE);
	if (NT_FAIL(ntRet))
	{
		DeleteObject(f, ModNameW->szBuffer);
		DeleteObject(f, ModNameW);

		DeleteObject(f, ModNameA->szBuffer);
		DeleteObject(f, ModNameA);

		return ntRet;
	}

	DeleteObject(f, ModNameA->szBuffer);
	DeleteObject(f, ModNameA);

	if (pData->OSVersion >= g_Win10)
	{
		LDRP_UNICODE_STRING_BUNDLE * pModPathW = NewObject<LDRP_UNICODE_STRING_BUNDLE>(f);
		if (!pModPathW)
		{
			DeleteObject(f, ModNameW->szBuffer);
			DeleteObject(f, ModNameW);

			return STATUS_NO_MEMORY;
		}

		pModPathW->String.MaxLength = sizeof(pModPathW->StaticBuffer);
		pModPathW->String.szBuffer	= pModPathW->StaticBuffer;

		LDRP_LOAD_CONTEXT_FLAGS ctx_flags{ 0 };
		ntRet = f->LdrpPreprocessDllName(ModNameW, pModPathW, nullptr, &ctx_flags);

		if (NT_FAIL(ntRet))
		{
			DeleteObject(f, pModPathW);
			DeleteObject(f, ModNameW->szBuffer);
			DeleteObject(f, ModNameW);

			return ntRet;
		}

		auto * ctx = NewObject<LDRP_PATH_SEARCH_CONTEXT>(f);
		if (!ctx)
		{
			DeleteObject(f, pModPathW);
			DeleteObject(f, ModNameW->szBuffer);
			DeleteObject(f, ModNameW);

			return STATUS_NO_MEMORY;
		}

		if (pData->OSBuildNumber == g_Win10_1511)
		{
			ReCa<LDRP_PATH_SEARCH_CONTEXT_1511 *>(ctx)->OriginalFullDllName = ModNameW->szBuffer;
		}
		else
		{
			ctx->OriginalFullDllName = ModNameW->szBuffer;
		}

		ULONG_PTR unknown3 = 0;

		if (pData->OSBuildNumber >= g_Win11_21H2)
		{
			auto _LdrpLoadDllInternal = ReCa<f_LdrpLoadDllInternal_WIN11>(f->LdrpLoadDllInternal);
			ntRet = _LdrpLoadDllInternal(&pModPathW->String, ctx, ctx_flags, 4, nullptr, nullptr, ReCa<LDR_DATA_TABLE_ENTRY_WIN11 **>(&entry_out), &unknown3, 0);
		}
		else
		{
			ntRet = f->LdrpLoadDllInternal(&pModPathW->String, ctx, ctx_flags, 4, nullptr, nullptr, ReCa<LDR_DATA_TABLE_ENTRY_WIN10 **>(&entry_out), &unknown3);
		}

		DeleteObject(f, ctx);
		DeleteObject(f, pModPathW);
	}
	else if (pData->OSVersion == g_Win81)
	{
		auto * ctx = NewObject<LDRP_PATH_SEARCH_CONTEXT_WIN81>(f);
		if (ctx)
		{
			ctx->OriginalFullDllName = ModNameW->szBuffer;

			LDRP_LOAD_CONTEXT_FLAGS ctx_flags{ 0 };
			LDR_DDAG_NODE_WIN81 * ddag_out = nullptr;

			auto _LdrpLoadDll = ReCa<f_LdrpLoadDll_WIN81>(f->LdrpLoadDll);
			ntRet = _LdrpLoadDll(ModNameW, ctx, ctx_flags, TRUE, ReCa<LDR_DATA_TABLE_ENTRY_WIN81 **>(&entry_out), &ddag_out);

			DeleteObject(f, ctx);
		}
		else
		{
			ntRet = STATUS_NO_MEMORY;
		}
	}
	else if (pData->OSVersion == g_Win8)
	{
		auto * ctx = NewObject<LDRP_PATH_SEARCH_CONTEXT_WIN8>(f);
		if (ctx)
		{
			ctx->OriginalFullDllName = ModNameW->szBuffer;
			ctx->unknown2 = TRUE;

			LDRP_LOAD_CONTEXT_FLAGS ctx_flags{ 0 };
			LDR_DDAG_NODE_WIN8 * ddag_out = nullptr;

			auto _LdrpLoadDll = ReCa<f_LdrpLoadDll_WIN8>(f->LdrpLoadDll);
			ntRet = _LdrpLoadDll(ModNameW, ctx, ctx_flags, TRUE, ReCa<LDR_DATA_TABLE_ENTRY_WIN8 **>(&entry_out), &ddag_out);

			DeleteObject(f, ctx);
		}
		else
		{
			ntRet = STATUS_NO_MEMORY;
		}		
	}
	else if (pData->OSVersion == g_Win7)
	{
		LDRP_LOAD_CONTEXT_FLAGS ctx_flags{ 0 };

		auto _LdrpLoadDll = ReCa<f_LdrpLoadDll_WIN7>(f->LdrpLoadDll);
		ntRet = _LdrpLoadDll(ModNameW, f->LdrpDefaultPath, ctx_flags, TRUE, nullptr, ReCa<LDR_DATA_TABLE_ENTRY_WIN7 **>(&entry_out));
	}
	else
	{
		ntRet = STATUS_NOT_IMPLEMENTED;
	}

	DeleteObject(f, ModNameW->szBuffer);
	DeleteObject(f, ModNameW); 
	
	if (NT_SUCCESS(ntRet))
	{
		if (entry_out)
		{
			*hModule = ReCa<HINSTANCE>(entry_out->DllBase);

			BuildDependencyRecord(f, head, ReCa<HANDLE>(*hModule));
		}
		else
		{
			ntRet = STATUS_DLL_NOT_FOUND;
		}
	}

	return ntRet;
}

__forceinline void UnloadAndDeleteDependencyRecord(MANUAL_MAPPING_FUNCTION_TABLE * f, MM_DEPENDENCY_RECORD * head)
{
	if (!head)
	{
		return;
	}

	//unload in reverse order, won't unload everything because dependency loading is fucked since Win 1.0
	auto cur = head->Prev;
	auto last = cur;
	do
	{
		f->LdrUnloadDll(cur->DllHandle);

		cur = cur->Prev;
		DeleteObject(f, cur->Next);
	}
	while (cur != last);
}

DWORD __declspec(code_seg(".mmap_sec$1")) __stdcall ManualMapping_Shell(MANUAL_MAPPING_DATA * pData)
{
	if (!pData)
	{
		return INJ_MM_ERR_NO_DATA;
	}

	BYTE * pAllocBase	= nullptr;
	BYTE * pBase		= nullptr;
	BYTE * pVEHShell	= nullptr;

	DWORD		Flags = pData->Flags;
	NTSTATUS	ntRet = STATUS_SUCCESS;
	HANDLE		hProc = NtCurrentProcess();

	//pe headers
	IMAGE_DOS_HEADER		* pDosHeader		= nullptr;
	IMAGE_NT_HEADERS		* pNtHeaders		= nullptr;
	IMAGE_OPTIONAL_HEADER	* pOptionalHeader	= nullptr;
	IMAGE_FILE_HEADER		* pFileHeader		= nullptr;

	//simple dependency record for unloading
	MM_DEPENDENCY_RECORD * imports			= nullptr;
	MM_DEPENDENCY_RECORD * delay_imports	= nullptr;

	//grab LdrpHeap pointer
	auto * f = &pData->f;
	f->pLdrpHeap = *f->LdrpHeap;

	if (!f->pLdrpHeap)
	{
		return INJ_MM_ERR_INVALID_HEAP_HANDLE;
	}

	//convert path to nt path
	UNICODE_STRING DllNtPath{ 0 };
	DllNtPath.Length	= pData->DllPath.Length;
	DllNtPath.MaxLength = sizeof(wchar_t[MAX_PATH + 4]);
	DllNtPath.szBuffer	= NewObject<wchar_t>(f, DllNtPath.MaxLength / sizeof(wchar_t));

	if (!DllNtPath.szBuffer)
	{
		return INJ_MM_ERR_HEAP_ALLOC;
	}

	//nt path prefix "\??\"
	f->memmove(DllNtPath.szBuffer + 0, pData->NtPathPrefix, sizeof(wchar_t[4]));
	f->memmove(DllNtPath.szBuffer + 4, pData->szPathBuffer, DllNtPath.Length);
	DllNtPath.Length += sizeof(wchar_t[4]);

	//update string buffer addresses
	UNICODE_STRING DllName = pData->DllName;
	DllName.szBuffer = pData->szNameBuffer;

	UNICODE_STRING DllPath = pData->DllPath;
	DllPath.szBuffer = pData->szPathBuffer;

	auto * oa = NewObject<OBJECT_ATTRIBUTES>(f);
	if (!oa)
	{
		DeleteObject(f, DllNtPath.szBuffer);

		return INJ_MM_ERR_HEAP_ALLOC;
	}

	InitializeObjectAttributes(oa, &DllNtPath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

	auto * io_status = NewObject<IO_STATUS_BLOCK>(f);
	if (!io_status)
	{
		DeleteObject(f, oa);
		DeleteObject(f, DllNtPath.szBuffer);

		return INJ_MM_ERR_HEAP_ALLOC;
	}

	HANDLE hDllFile = nullptr;

	//open dll file
	ntRet = f->NtOpenFile(&hDllFile, FILE_GENERIC_READ, oa, io_status, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

	DeleteObject(f, oa);
	DeleteObject(f, DllNtPath.szBuffer);

	if (NT_FAIL(ntRet))
	{
		pData->ntRet = ntRet;

		DeleteObject(f, io_status);

		return INJ_MM_ERR_NT_OPEN_FILE;
	}

	auto * fsi = NewObject<FILE_STANDARD_INFO>(f);
	if (!fsi)
	{
		DeleteObject(f, io_status);

		f->NtClose(hDllFile);

		return INJ_MM_ERR_HEAP_ALLOC;
	}

	//query basic file information
	ntRet = f->NtQueryInformationFile(hDllFile, io_status, fsi, sizeof(FILE_STANDARD_INFO), FILE_INFORMATION_CLASS::FileStandardInformation);
	if (NT_FAIL(ntRet))
	{
		pData->ntRet = ntRet;

		DeleteObject(f, fsi);
		DeleteObject(f, io_status);

		f->NtClose(hDllFile);

		return INJ_MM_ERR_CANT_GET_FILE_SIZE;
	}

	BYTE * pRawData = nullptr;
	SIZE_T RawSize = fsi->AllocationSize.LowPart;

	//allocate memory for the raw dll file
	ntRet = f->NtAllocateVirtualMemory(hProc, ReCa<void **>(&pRawData), 0, &RawSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (NT_FAIL(ntRet))
	{
		pData->ntRet = ntRet;

		DeleteObject(f, fsi);
		DeleteObject(f, io_status);

		f->NtClose(hDllFile);

		return INJ_MM_ERR_MEMORY_ALLOCATION_FAILED;
	}

	auto * pos = NewObject<FILE_POSITION_INFORMATION>(f);
	if (!pos)
	{
		DeleteObject(f, fsi);
		DeleteObject(f, io_status);

		RawSize = 0;
		f->NtFreeVirtualMemory(hProc, ReCa<void **>(&pRawData), &RawSize, MEM_RELEASE);
		f->NtClose(hDllFile);

		return INJ_MM_ERR_HEAP_ALLOC;
	}

	//reset file pointer
	ntRet = f->NtSetInformationFile(hDllFile, io_status, pos, sizeof(FILE_POSITION_INFORMATION), FILE_INFORMATION_CLASS::FilePositionInformation);
	if (NT_FAIL(ntRet))
	{
		pData->ntRet = ntRet;

		DeleteObject(f, fsi);
		DeleteObject(f, io_status);

		RawSize = 0;
		f->NtFreeVirtualMemory(hProc, ReCa<void **>(&pRawData), &RawSize, MEM_RELEASE);
		f->NtClose(hDllFile);

		return INJ_MM_ERR_SET_FILE_POSITION;
	}

	DeleteObject(f, pos);

	//read raw dll file into memory
	ntRet = f->NtReadFile(hDllFile, nullptr, nullptr, nullptr, io_status, pRawData, fsi->AllocationSize.LowPart, nullptr, nullptr);
	if (NT_FAIL(ntRet))
	{
		pData->ntRet = ntRet;

		DeleteObject(f, fsi);
		DeleteObject(f, io_status);

		RawSize = 0;
		f->NtFreeVirtualMemory(hProc, ReCa<void **>(&pRawData), &RawSize, MEM_RELEASE);
		f->NtClose(hDllFile);

		return INJ_MM_ERR_NT_READ_FILE;
	}

	DeleteObject(f, fsi);
	DeleteObject(f, io_status);

	//grab pe header pointers (assuming the file is a valid dll)
	pDosHeader		= ReCa<IMAGE_DOS_HEADER *>(pRawData);
	pNtHeaders		= ReCa<IMAGE_NT_HEADERS *>(pRawData + pDosHeader->e_lfanew);
	pOptionalHeader	= &pNtHeaders->OptionalHeader;
	pFileHeader		= &pNtHeaders->FileHeader;

	SIZE_T ImgSize = static_cast<SIZE_T>(pOptionalHeader->SizeOfImage);

	//update allocation size depending on flags
	if (Flags & INJ_MM_SHIFT_MODULE_BASE && !(Flags & INJ_MM_SET_PAGE_PROTECTIONS))
	{
		ImgSize += pData->ShiftOffset;
	}

	if (Flags & INJ_MM_ENABLE_EXCEPTIONS)
	{
		ImgSize += 0x1000;
	}

	//allocate memory for the dll
	ntRet = f->NtAllocateVirtualMemory(hProc, ReCa<void **>(&pAllocBase), 0, &ImgSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (NT_FAIL(ntRet))
	{
		pData->ntRet = ntRet;

		RawSize = 0;
		f->NtFreeVirtualMemory(hProc, ReCa<void **>(&pRawData), &RawSize, MEM_RELEASE);
		f->NtClose(hDllFile);

		return INJ_MM_ERR_MEMORY_ALLOCATION_FAILED;
	}

	//update pointers depending on flags
	if (Flags & INJ_MM_SHIFT_MODULE_BASE && !(Flags & INJ_MM_SET_PAGE_PROTECTIONS))
	{
		pBase = pAllocBase + pData->ShiftOffset;
	}
	else
	{
		pBase = pAllocBase;
	}

	bool veh_shell_fixed = false;

	if (Flags & INJ_MM_ENABLE_EXCEPTIONS)
	{
		pVEHShell = pBase + pOptionalHeader->SizeOfImage;

		auto * veh_shell_data = NewObject<VEH_SHELL_DATA>(f);

		if (veh_shell_data)
		{
			veh_shell_data->ImgBase		= ReCa<ULONG_PTR>(pBase);
			veh_shell_data->ImgSize		= pOptionalHeader->SizeOfImage;
			veh_shell_data->OSVersion	= pData->OSVersion;
			veh_shell_data->_LdrpInvertedFunctionTable	= f->LdrpInvertedFunctionTable;
			veh_shell_data->_LdrProtectMrdata			= f->LdrProtectMrdata;

			veh_shell_fixed = FindAndReplacePtr(pData->pVEHShell, pData->VEHShellSize, VEHDATASIG, ReCa<UINT_PTR>(veh_shell_data));
		}

		if (veh_shell_fixed)
		{
			//copy VEH shellcode into target location
			f->memmove(pVEHShell, pData->pVEHShell, pData->VEHShellSize);
		}
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

	//update pe headers to the new location
	pDosHeader		= ReCa<IMAGE_DOS_HEADER *>(pBase);
	pNtHeaders		= ReCa<IMAGE_NT_HEADERS *>(pBase + pDosHeader->e_lfanew);
	pOptionalHeader = &pNtHeaders->OptionalHeader;
	pFileHeader		= &pNtHeaders->FileHeader;

	RawSize = 0;
	f->NtFreeVirtualMemory(hProc, ReCa<void **>(&pRawData), &RawSize, MEM_RELEASE);

	BYTE * LocationDelta = pBase - pOptionalHeader->ImageBase;

	//relocate the image if necessary
	if (LocationDelta)
	{
		auto * pRelocDir = ReCa<IMAGE_DATA_DIRECTORY *>(&pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

		if (!pRelocDir->Size)
		{
			ImgSize = 0;
			f->NtFreeVirtualMemory(hProc, ReCa<void **>(&pAllocBase), &ImgSize, MEM_RELEASE);
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

			if (pRelocData >= ReCa<IMAGE_BASE_RELOCATION *>(pBase + pRelocDir->VirtualAddress + pRelocDir->Size))
			{
				break;
			}
		}

		pOptionalHeader->ImageBase += ReCa<ULONG_PTR>(LocationDelta);
	}

	//initialize security cookie
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

	//resolve imports
	if (Flags & (INJ_MM_RESOLVE_IMPORTS | INJ_MM_RUN_DLL_MAIN))
	{
		IMAGE_DATA_DIRECTORY	* pImportDir	= ReCa<IMAGE_DATA_DIRECTORY *>(&pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
		IMAGE_IMPORT_DESCRIPTOR * pImportDescr	= nullptr;

		if (pImportDir->Size)
		{
			pImportDescr = ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pBase + pImportDir->VirtualAddress);
		}

		bool ErrorBreak = false;

		while (pImportDescr && pImportDescr->Name)
		{
			//grab import name
			char * szMod = ReCa<char *>(pBase + pImportDescr->Name);
			
			//load import
			HINSTANCE hDll = NULL;
			ntRet = LoadModule(pData, f, szMod, &hDll, &imports);

			if (NT_FAIL(ntRet))
			{
				//unable to load required library
				ErrorBreak = true;
				break;
			}

			//grab import data
			IMAGE_THUNK_DATA * pThunk	= ReCa<IMAGE_THUNK_DATA *>(pBase + pImportDescr->OriginalFirstThunk);
			IMAGE_THUNK_DATA * pIAT		= ReCa<IMAGE_THUNK_DATA *>(pBase + pImportDescr->FirstThunk);

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
					//by ordinal
					ntRet = f->LdrGetProcedureAddress(ReCa<void *>(hDll), nullptr, IMAGE_ORDINAL(pThunk->u1.Ordinal), ReCa<void **>(pFuncRef));
				}
				else
				{
					//by name
					pImport = ReCa<IMAGE_IMPORT_BY_NAME *>(pBase + (pThunk->u1.AddressOfData));

					//convert c string import into ANSI_STRING
					auto * import = NewObject<ANSI_STRING>(f);
					if (!import)
					{
						ErrorBreak = true;
						break;
					}

					import->szBuffer	= pImport->Name;
					import->Length		= SizeAnsiString(import->szBuffer);
					import->MaxLength	= import->Length + 1 * sizeof(char);

					//load imported function address and save to IAT
					ntRet = f->LdrGetProcedureAddress(ReCa<void *>(hDll), import, IMAGE_ORDINAL(pThunk->u1.Ordinal), ReCa<void **>(pFuncRef));

					DeleteObject(f, import);
				}

				if (NT_FAIL(ntRet))
				{
					//unable to resolve function address
					ErrorBreak = true;
					break;
				}
			}

			if (ErrorBreak)
			{
				break;
			}

			++pImportDescr;

			//range check in some cases necessary, if(pImportDescr->Name) might not be sufficient
			if (pImportDescr >= ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pBase + pImportDir->VirtualAddress + pImportDir->Size))
			{
				break;
			}
		}

		if (ErrorBreak)
		{
			pData->ntRet = ntRet;
		
			UnloadAndDeleteDependencyRecord(f, imports);

			ImgSize = 0;
			f->NtFreeVirtualMemory(hProc, ReCa<void **>(&pAllocBase), &ImgSize, MEM_RELEASE);
			f->NtClose(hDllFile);

			return INJ_MM_ERR_IMPORT_FAIL;
		}
	}

	//resolve delay imports
	//this normally is done at runtime and completely optional
	//see regular import loading
	if (Flags & INJ_MM_RESOLVE_DELAY_IMPORTS)
	{
		IMAGE_DATA_DIRECTORY * pDelayImportDir = ReCa<IMAGE_DATA_DIRECTORY *>(&pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]);
		IMAGE_DELAYLOAD_DESCRIPTOR * pDelayImportDescr = nullptr;

		if (pDelayImportDir->Size)
		{
			pDelayImportDescr = ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pBase + pDelayImportDir->VirtualAddress);
		}

		bool ErrorBreak = false;

		while (pDelayImportDescr && pDelayImportDescr->DllNameRVA)
		{
			char * szMod = ReCa<char *>(pBase + pDelayImportDescr->DllNameRVA);
			
			HINSTANCE hDll = NULL;
			ntRet = LoadModule(pData, f, szMod, &hDll, &delay_imports);

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

			IMAGE_THUNK_DATA * pIAT			= ReCa<IMAGE_THUNK_DATA *>(pBase + pDelayImportDescr->ImportAddressTableRVA);
			IMAGE_THUNK_DATA * pNameTable	= ReCa<IMAGE_THUNK_DATA *>(pBase + pDelayImportDescr->ImportNameTableRVA);

			for (; pIAT->u1.Function; ++pIAT, ++pNameTable)
			{
				if (IMAGE_SNAP_BY_ORDINAL(pNameTable->u1.Ordinal))
				{
					f->LdrGetProcedureAddress(ReCa<void *>(hDll), nullptr, IMAGE_ORDINAL(pNameTable->u1.Ordinal), ReCa<void **>(pIAT));
				}
				else
				{
					auto pImport = ReCa<IMAGE_IMPORT_BY_NAME *>(pBase + (pNameTable->u1.AddressOfData));

					auto * import = NewObject<ANSI_STRING>(f);
					if (!import)
					{
						ErrorBreak = true;
						break;
					}

					import->szBuffer	= pImport->Name;
					import->Length		= SizeAnsiString(import->szBuffer);
					import->MaxLength	= import->Length + 1 * sizeof(char);

					ntRet = f->LdrGetProcedureAddress(ReCa<void *>(hDll), import, IMAGE_ORDINAL(pNameTable->u1.Ordinal), ReCa<void **>(pIAT));

					DeleteObject(f, import);
				}

				if (NT_FAIL(ntRet))
				{
					ErrorBreak = true;
					break;
				}
			}

			++pDelayImportDescr;

			if (pDelayImportDescr >= ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pBase + pDelayImportDir->VirtualAddress + pDelayImportDir->Size))
			{
				break;
			}
		}

		if (ErrorBreak)
		{
			pData->ntRet = ntRet;

			UnloadAndDeleteDependencyRecord(f, delay_imports);
			UnloadAndDeleteDependencyRecord(f, imports);

			ImgSize = 0;
			f->NtFreeVirtualMemory(hProc, ReCa<void **>(&pAllocBase), &ImgSize, MEM_RELEASE);
			f->NtClose(hDllFile);

			return INJ_MM_ERR_DELAY_IMPORT_FAIL;
		}
	}

	//update page protections
	if (Flags & INJ_MM_SET_PAGE_PROTECTIONS)
	{
		ULONG OldProtection = 0;
		SIZE_T SizeOut = pOptionalHeader->SizeOfHeaders;
		ntRet = f->NtProtectVirtualMemory(hProc, ReCa<void **>(&pBase), &SizeOut, PAGE_EXECUTE_READ, &OldProtection);

		if (NT_SUCCESS(ntRet))
		{
			//iterate over all the previously mapped sections
			pCurrentSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
			for (UINT i = 0; i != pFileHeader->NumberOfSections; ++i, ++pCurrentSectionHeader)
			{
				void * pSectionBase = pBase + pCurrentSectionHeader->VirtualAddress;
				DWORD characteristics = pCurrentSectionHeader->Characteristics;
				SIZE_T SectionSize = pCurrentSectionHeader->SizeOfRawData;

				if (SectionSize)
				{
					//identify protection state for current section
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

					//update page protection
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

			UnloadAndDeleteDependencyRecord(f, delay_imports);
			UnloadAndDeleteDependencyRecord(f, imports);

			ImgSize = 0;
			f->NtFreeVirtualMemory(hProc, ReCa<void **>(&pAllocBase), &ImgSize, MEM_RELEASE);
			f->NtClose(hDllFile);

			return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
		}
	}

	if (Flags & INJ_MM_ENABLE_EXCEPTIONS)
	{
		//try RtlInsertInvertedFunctionTable first
		if (pData->OSVersion >= g_Win81)
		{
			f->RtlInsertInvertedFunctionTable(pBase, pOptionalHeader->SizeOfImage);
		}
		else if (pData->OSVersion == g_Win8)
		{
			auto _RtlInsertInvertedFunctionTable = ReCa<f_RtlInsertInvertedFunctionTable_WIN8>(f->RtlInsertInvertedFunctionTable);
			_RtlInsertInvertedFunctionTable(pBase, pOptionalHeader->SizeOfImage);
		}
		else if (pData->OSVersion == g_Win7)
		{
			auto _RtlInsertInvertedFunctionTable = ReCa<f_RtlInsertInvertedFunctionTable_WIN7>(f->RtlInsertInvertedFunctionTable);
			_RtlInsertInvertedFunctionTable(ReCa<RTL_INVERTED_FUNCTION_TABLE_WIN7 *>(f->LdrpInvertedFunctionTable), pBase, pOptionalHeader->SizeOfImage);
		}

		ntRet = STATUS_DLL_NOT_FOUND;
		bool partial = true;
		
#ifdef _WIN64
		if (veh_shell_fixed)
		{
			//register VEH shell to fill handler list
			pData->hVEH = f->RtlAddVectoredExceptionHandler(0, ReCa<PVECTORED_EXCEPTION_HANDLER>(pVEHShell));
		}
#endif

		//check LdrpInvertedFunctionTable if module exists
		for (ULONG i = 0; i < f->LdrpInvertedFunctionTable->Count; ++i)
		{
			RTL_INVERTED_FUNCTION_TABLE_ENTRY * entry = nullptr;
			if (pData->OSVersion >= g_Win8)
			{
				entry = &f->LdrpInvertedFunctionTable->Entries[i];
			}
			else
			{
				entry = &ReCa<RTL_INVERTED_FUNCTION_TABLE_WIN7 *>(f->LdrpInvertedFunctionTable)->Entries[i];
			}
			
			if (entry->ImageBase != pBase)
			{
				continue;
			}

			if (entry->ExceptionDirectorySize)
			{
				//module exists, entries have been initialized
				partial = false;
				ntRet = STATUS_SUCCESS;

				break;
			}
						
			//module exists, entries don't
			//create fake entry which will be filled at runtime using a VEH shell
			void * pFakeExceptionDir	= nullptr;
			SIZE_T FakeDirSize			= 0x800 * sizeof(void *);
			ntRet = f->NtAllocateVirtualMemory(hProc, &pFakeExceptionDir, 0, &FakeDirSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

			if (NT_FAIL(ntRet))
			{
				break;
			}

			//EncodeSystemPointer
			UINT_PTR pRaw	= ReCa<UINT_PTR>(pFakeExceptionDir);
			auto cookie		= *P_KUSER_SHARED_DATA_COOKIE;

#ifdef _WIN64
			UINT_PTR pEncoded = bit_rotate_r(cookie ^ pRaw, cookie & 0x3F);
#else
			UINT_PTR pEncoded = bit_rotate_r(cookie ^ pRaw, cookie & 0x1F);
#endif
			
			if (pData->OSVersion >= g_Win81)
			{
				f->LdrProtectMrdata(FALSE);
			}

			entry->ExceptionDirectory = ReCa<IMAGE_RUNTIME_FUNCTION_ENTRY *>(pEncoded);

			if (pData->OSVersion >= g_Win81)
			{
				f->LdrProtectMrdata(TRUE);
			}

			if (veh_shell_fixed && !pData->hVEH)
			{
				//register VEH shell to fill handler list
				pData->hVEH = f->RtlAddVectoredExceptionHandler(0, ReCa<PVECTORED_EXCEPTION_HANDLER>(pVEHShell));
			}

			break;
		}

#ifdef _WIN64
		if (NT_SUCCESS(ntRet) && partial)
		{
			//on x64 also try documented method
			auto size = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
			if (size)
			{
				auto * pExceptionHandlers = ReCa<RUNTIME_FUNCTION *>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
				auto EntryCount = size / sizeof(RUNTIME_FUNCTION);

				if (!f->RtlAddFunctionTable(pExceptionHandlers, MDWD(EntryCount), ReCa<DWORD64>(pBase)))
				{
					ntRet = STATUS_UNSUCCESSFUL;
				}
			}
			else
			{
				ntRet = STATUS_UNSUCCESSFUL;
			}
		}
#endif

		if (NT_FAIL(ntRet))
		{
			pData->ntRet = ntRet;

			if (pData->hVEH)
			{
				f->RtlRemoveVectoredExceptionHandler(pData->hVEH);
			}

			UnloadAndDeleteDependencyRecord(f, delay_imports);
			UnloadAndDeleteDependencyRecord(f, imports);

			ImgSize = 0;
			f->NtFreeVirtualMemory(hProc, ReCa<void **>(&pAllocBase), &ImgSize, MEM_RELEASE);
			f->NtClose(hDllFile);

			return INJ_MM_ERR_ENABLING_SEH_FAILED;
		}
	}

	//initialized static TLS and call TLS callbacks
	if ((Flags & INJ_MM_EXECUTE_TLS) && pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		auto * pTLS = ReCa<IMAGE_TLS_DIRECTORY *>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

		auto * pDummyLdr = NewObject<LDR_DATA_TABLE_ENTRY>(f);
		if (!pDummyLdr)
		{
			UnloadAndDeleteDependencyRecord(f, delay_imports);
			UnloadAndDeleteDependencyRecord(f, imports);

			ImgSize = 0;
			f->NtFreeVirtualMemory(hProc, ReCa<void **>(&pAllocBase), &ImgSize, MEM_RELEASE);
			f->NtClose(hDllFile);

			return INJ_MM_ERR_HEAP_ALLOC;
		}

		//LdrpHandleTlsData either crashes or returns STATUS_SUCCESS -> no point in error checking
		//it also only accesses the DllBase member of the ldr entry thus a dummy ldr entry is sufficient

		pDummyLdr->DllBase = pBase;

		if (pData->OSVersion <= g_Win8)
		{
			//Win7 & Win8 __stdcall
			auto _LdrpHandleTlsData = ReCa<f_LdrpHandleTlsData_WIN8>(f->LdrpHandleTlsData);
			_LdrpHandleTlsData(ReCa<LDR_DATA_TABLE_ENTRY_WIN8 *>(pDummyLdr));
		}
		else
		{
			//Win8.1+ __fastcall
			f->LdrpHandleTlsData(pDummyLdr);
		}		

		auto * pCallback = ReCa<PIMAGE_TLS_CALLBACK *>(pTLS->AddressOfCallBacks);
		for (; pCallback && (*pCallback); ++pCallback)
		{
			auto Callback = *pCallback;
			Callback(pBase, DLL_PROCESS_ATTACH, nullptr);
		}

		auto current = f->LdrpTlsList->Flink;
		while (current != f->LdrpTlsList)
		{
			auto entry = ReCa<TLS_ENTRY *>(current);
			if (entry->ModuleEntry == pDummyLdr)
			{
				entry->ModuleEntry = nullptr;

				break;
			}

			current = current->Flink;
		}
		
		DeleteObject(f, pDummyLdr);
	}

	//run DllMain
	if (Flags & INJ_MM_RUN_DLL_MAIN && pOptionalHeader->AddressOfEntryPoint)
	{
		ULONG		State	= 0;
		ULONG_PTR	Cookie	= 0;
		bool		locked	= false;

		if (Flags & INJ_MM_RUN_UNDER_LDR_LOCK)
		{
			ntRet = f->LdrLockLoaderLock(NULL, &State, &Cookie);
			
			//don't interrupt only because loader lock wasn't acquired
			locked = NT_SUCCESS(ntRet);
		}

		f_DLL_ENTRY_POINT DllMain = ReCa<f_DLL_ENTRY_POINT>(pBase + pOptionalHeader->AddressOfEntryPoint);
		DllMain(ReCa<HINSTANCE>(pBase), DLL_PROCESS_ATTACH, nullptr);

		if ((Flags & INJ_MM_RUN_UNDER_LDR_LOCK) && locked)
		{
			f->LdrUnlockLoaderLock(NULL, Cookie);
		}
	}

	//remove unnecesary data from the PE header
	if (Flags & INJ_MM_CLEAN_DATA_DIR && !(Flags & INJ_MM_SET_PAGE_PROTECTIONS))
	{
		//remove strings from the import directory
		DWORD Size = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
		if (Size)
		{
			auto * pImportDescr = ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
			while (pImportDescr->Name)
			{
				char * szMod = ReCa<char *>(pBase + pImportDescr->Name);
				for (; *szMod++; *szMod = '\0');
				pImportDescr->Name = 0;

				IMAGE_THUNK_DATA * pThunk	= ReCa<IMAGE_THUNK_DATA *>(pBase + pImportDescr->OriginalFirstThunk);
				IMAGE_THUNK_DATA * pIAT		= ReCa<IMAGE_THUNK_DATA *>(pBase + pImportDescr->FirstThunk);

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

		//remove strings from the delay import directory
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

		//remove debug data
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

		//remove base relocation information
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

		//remove TLS callback information
		Size = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
		if (Size)
		{
			auto * pTLS = ReCa<IMAGE_TLS_DIRECTORY *>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
			auto * pCallback = ReCa<PIMAGE_TLS_CALLBACK *>(pTLS->AddressOfCallBacks);
			for (; pCallback && (*pCallback); ++pCallback)
			{
				*pCallback = nullptr;
			}

			pTLS->AddressOfCallBacks	= 0;
			pTLS->AddressOfIndex		= 0;
			pTLS->EndAddressOfRawData	= 0;
			pTLS->SizeOfZeroFill		= 0;
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

		//PE header is R/E only
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
			//grab ntdll from the ldr

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

		//update PE header protection back to R/E
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

	NT_FUNC_CONSTRUCTOR_INIT(NtCreateSection);
	NT_FUNC_CONSTRUCTOR_INIT(NtMapViewOfSection);

	NT_FUNC_CONSTRUCTOR_INIT(memmove);
	NT_FUNC_CONSTRUCTOR_INIT(RtlZeroMemory);
	NT_FUNC_CONSTRUCTOR_INIT(RtlAllocateHeap);
	NT_FUNC_CONSTRUCTOR_INIT(RtlFreeHeap);

	NT_FUNC_CONSTRUCTOR_INIT(LdrpLoadDll);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpLoadDllInternal);
	NT_FUNC_CONSTRUCTOR_INIT(LdrGetProcedureAddress);

	NT_FUNC_CONSTRUCTOR_INIT(LdrUnloadDll);

	NT_FUNC_CONSTRUCTOR_INIT(RtlAnsiStringToUnicodeString);

	NT_FUNC_CONSTRUCTOR_INIT(LdrpPreprocessDllName);
	NT_FUNC_CONSTRUCTOR_INIT(RtlInsertInvertedFunctionTable);
#ifdef _WIN64
	NT_FUNC_CONSTRUCTOR_INIT(RtlAddFunctionTable);
#endif
	NT_FUNC_CONSTRUCTOR_INIT(LdrpHandleTlsData);

	NT_FUNC_CONSTRUCTOR_INIT(LdrLockLoaderLock);
	NT_FUNC_CONSTRUCTOR_INIT(LdrUnlockLoaderLock);

	NT_FUNC_CONSTRUCTOR_INIT(LdrProtectMrdata);

	NT_FUNC_CONSTRUCTOR_INIT(RtlAddVectoredExceptionHandler);
	NT_FUNC_CONSTRUCTOR_INIT(RtlRemoveVectoredExceptionHandler);

	NT_FUNC_CONSTRUCTOR_INIT(LdrpModuleBaseAddressIndex);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpMappingInfoIndex);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpHeap);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpInvertedFunctionTable);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpDefaultPath);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpTlsList);

	pLdrpHeap = nullptr;
}