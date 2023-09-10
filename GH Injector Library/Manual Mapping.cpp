/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

#include "pch.h"

#include "Manual Mapping.h"

using namespace NATIVE;
using namespace MMAP_NATIVE;

DWORD MMAP_NATIVE::ManualMap(const INJECTION_SOURCE & Source, HANDLE hTargetProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD Timeout, ERROR_DATA & error_data)
{
#if !defined(_WIN64) && defined (DUMP_SHELLCODE)
	DUMP_WOW64(ManualMapping_Shell,			MMI_MapSections);
	DUMP_WOW64(MMI_MapSections,				MMI_RelocateImage);
	DUMP_WOW64(MMI_RelocateImage,			MMI_InitializeCookie);
	DUMP_WOW64(MMI_InitializeCookie,		MMI_LoadImports);
	DUMP_WOW64(MMI_LoadImports,				MMI_LoadDelayImports);
	DUMP_WOW64(MMI_LoadDelayImports,		MMI_SetPageProtections);
	DUMP_WOW64(MMI_SetPageProtections,		MMI_EnableExceptions);
	DUMP_WOW64(MMI_EnableExceptions,		MMI_HandleTLS);
	DUMP_WOW64(MMI_HandleTLS,				MMI_ExecuteDllMain);
	DUMP_WOW64(MMI_ExecuteDllMain,			MMI_CleanDataDirectories);
	DUMP_WOW64(MMI_CleanDataDirectories,	MMI_CloakHeader);
	DUMP_WOW64(MMI_CloakHeader,				MMI_CleanUp);
	DUMP_WOW64(MMI_CleanUp,					MMIH_ResolveFilePath);
	DUMP_WOW64(MMIH_ResolveFilePath,		MMIH_PreprocessModuleName);
	DUMP_WOW64(MMIH_PreprocessModuleName,	MMIH_LoadModule);
	DUMP_WOW64(MMIH_LoadModule,				MMAP_SEC_END);

	DUMP_WOW64(VectoredHandlerShell, VEH_SEC_END);

	return INJ_ERR_SHELLCODE_DUMPED;
#endif

	LOG(1, "Begin ManualMap\n");

	MANUAL_MAPPING_DATA data{ 0 };
	data.Flags			= Flags;
	data.OSVersion		= GetOSVersion();
	data.OSBuildNumber	= GetOSBuildVersion();

	if (Source.FromMemory)
	{
		data.RawSize = Source.RawSize;
	}
	else
	{
		size_t len		= Source.DllPath.length();
		size_t max_len	= sizeof(data.szPathBuffer) / sizeof(wchar_t);
		if (len > max_len)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(1, "Path too long: %d characters, buffer size: %d\n", len, max_len);

			return INJ_ERR_STRING_TOO_LONG;
		}

		data.DllPath.Length		= (WORD)(len * sizeof(wchar_t));
		data.DllPath.MaxLength	= (WORD)sizeof(data.szPathBuffer);
		Source.DllPath.copy(data.szPathBuffer, Source.DllPath.length());
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

	//.mmap_sec include mapping functions and helper functions
	ULONG_PTR ShellSize		= ReCa<ULONG_PTR>(MMAP_SEC_END) - ReCa<ULONG_PTR>(ManualMapping_Shell);

	//.veh_sec currently only contains handler shell
	ULONG_PTR VEHShellSize	= ReCa<ULONG_PTR>(VEH_SEC_END) - ReCa<ULONG_PTR>(VectoredHandlerShell);
	
	//ignore VEH shell if exceptions aren't enabled
	if (!(Flags & INJ_MM_ENABLE_EXCEPTIONS))
	{
		VEHShellSize = 0;
	}

	auto AllocationSize = sizeof(MANUAL_MAPPING_DATA) + sizeof(MANUAL_MAPPING_FUNCTION_TABLE) + ShellSize + VEHShellSize + BASE_ALIGNMENT * 4;
	if (Source.FromMemory)
	{
		AllocationSize += (SIZE_T)Source.RawSize + BASE_ALIGNMENT;
	}

	BYTE * pAllocBase = ReCa<BYTE *>(VirtualAllocEx(hTargetProc, nullptr, AllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pAllocBase)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "memory allocation failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_OUT_OF_MEMORY_EXT;
	}

	BYTE * pArg				= pAllocBase;
	BYTE * pShells			= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pArg)			+ sizeof(MANUAL_MAPPING_DATA),				BASE_ALIGNMENT));
	BYTE * pVEHShell		= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pShells)		+ ShellSize,								BASE_ALIGNMENT));
	BYTE * pFunctionTable	= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pVEHShell)		+ VEHShellSize,								BASE_ALIGNMENT));
	BYTE * pRawData			= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pFunctionTable) + sizeof(MANUAL_MAPPING_FUNCTION_TABLE),	BASE_ALIGNMENT));

	auto table_local = new(std::nothrow) MANUAL_MAPPING_FUNCTION_TABLE();
	if (!table_local)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "operator new failed: %08X\n", error_data.AdvErrorCode);

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_OUT_OF_MEMORY_NEW;
	}

	//initialze local function table with remote addresses
	BYTE * mmap_sec_base = ReCa<BYTE *>(ManualMapping_Shell);

	table_local->MMP_Shell = ReCa<f_MMI_FUNCTION>(pShells);
	table_local->MMIP_MapSections			= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_MapSections)				- mmap_sec_base));
	table_local->MMIP_RelocateImage			= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_RelocateImage)			- mmap_sec_base));
	table_local->MMIP_InitializeCookie		= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_InitializeCookie)		- mmap_sec_base));
	table_local->MMIP_LoadImports			= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_LoadImports)				- mmap_sec_base));
	table_local->MMIP_LoadDelayImports		= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_LoadDelayImports)		- mmap_sec_base));
	table_local->MMIP_SetPageProtections	= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_SetPageProtections)		- mmap_sec_base));
	table_local->MMIP_EnableExceptions		= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_EnableExceptions)		- mmap_sec_base));
	table_local->MMIP_HandleTLS				= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_HandleTLS)				- mmap_sec_base));
	table_local->MMIP_ExecuteDllMain		= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_ExecuteDllMain)			- mmap_sec_base));
	table_local->MMIP_CleanDataDirectories	= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_CleanDataDirectories)	- mmap_sec_base));
	table_local->MMIP_CloakHeader			= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_CloakHeader)				- mmap_sec_base));
	table_local->MMIP_CleanUp				= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_CleanUp)					- mmap_sec_base));
	
	table_local->MMIHP_ResolveFilePath			= ReCa<decltype(MMIH_ResolveFilePath)			*>(pShells + (ReCa<BYTE *>(MMIH_ResolveFilePath)			- mmap_sec_base));
	table_local->MMIHP_PreprocessModuleName		= ReCa<decltype(MMIH_PreprocessModuleName)		*>(pShells + (ReCa<BYTE *>(MMIH_PreprocessModuleName)		- mmap_sec_base));
	table_local->MMIHP_LoadModule				= ReCa<decltype(MMIH_LoadModule)				*>(pShells + (ReCa<BYTE *>(MMIH_LoadModule)					- mmap_sec_base));

	data.FunctionTable = ReCa<MANUAL_MAPPING_FUNCTION_TABLE *>(pFunctionTable);

	if (VEHShellSize)
	{
		data.pVEHShell		= pVEHShell;
		data.VEHShellSize	= MDWD(VEHShellSize);
	}

	if (Source.FromMemory)
	{
		data.pRawData = pRawData;
	}

	LOG(2, "Shellsize      = %08X\n", MDWD(ShellSize));
	LOG(2, "Total size     = %08X\n", MDWD(AllocationSize));
	LOG(2, "pArg           = %p\n", pArg);
	LOG(2, "pShells        = %p\n", pShells);

	if (VEHShellSize)
	{
		LOG(2, "pVEHShell      = %p\n", data.pVEHShell);
	}

	LOG(2, "pFunctionTable = %p\n", pFunctionTable);

	if (!WriteProcessMemory(hTargetProc, pArg, &data, sizeof(MANUAL_MAPPING_DATA), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		delete table_local;
		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	LOG(1, "Shelldata written to memory\n");

	if (!WriteProcessMemory(hTargetProc, pShells, mmap_sec_base, ShellSize, nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		delete table_local;
		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	LOG(1, "Shells written to memory\n");

	if (VEHShellSize)
	{
		if (!WriteProcessMemory(hTargetProc, pVEHShell, VectoredHandlerShell, VEHShellSize, nullptr))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(1, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

			delete table_local;
			VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

			return INJ_ERR_WPM_FAIL;
		}

		LOG(1, "VEH shell written to memory\n");
	}

	if (!WriteProcessMemory(hTargetProc, pFunctionTable, table_local, sizeof(MANUAL_MAPPING_FUNCTION_TABLE), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		delete table_local;
		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	LOG(1, "Function table written to memory\n");

	delete table_local;

	if (Source.FromMemory)
	{
		if (!WriteProcessMemory(hTargetProc, pRawData, Source.RawData, Source.RawSize, nullptr))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(1, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

			VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

			return INJ_ERR_WPM_FAIL;
		}

		LOG(1, "Raw data written to memory\n");
	}

	if (Flags & INJ_THREAD_CREATE_CLOAKED)
	{
		Flags |= (INJ_CTF_FAKE_START_ADDRESS | INJ_CTF_HIDE_FROM_DEBUGGER);
	}

	DWORD remote_ret = 0;
	DWORD dwRet = StartRoutine(hTargetProc, ReCa<f_Routine>(pShells), pArg, Method, Flags, remote_ret, Timeout, error_data);

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

#pragma region inlined dependency record functions

__forceinline MM_DEPENDENCY_RECORD * BuildDependencyRecord(MANUAL_MAPPING_FUNCTION_TABLE * f, MM_DEPENDENCY_RECORD ** head, HANDLE DllHandle, const UNICODE_STRING * DllPath)
{
	if (!head)
	{
		return nullptr;
	}

	//create new list (head)
	if (!(*head))
	{
		*head = NewObject<MM_DEPENDENCY_RECORD>(f);

		if (!(*head))
		{
			return nullptr;
		}

		(*head)->Next = *head;
		(*head)->Prev = *head;
		(*head)->DllHandle = DllHandle;
		
		if (DllPath)
		{
			auto len = DllPath->Length;
			if (len < sizeof(MM_DEPENDENCY_RECORD::Buffer))
			{
				(*head)->DllName.Length		= len;
				(*head)->DllName.MaxLength	= sizeof(MM_DEPENDENCY_RECORD::Buffer);
				(*head)->DllName.szBuffer	= (*head)->Buffer;

				f->memmove((*head)->Buffer, DllPath->szBuffer, len);
			}
		}

		return (*head);
	}	

	//create new entry
	auto next = NewObject<MM_DEPENDENCY_RECORD>(f);
	if (next)
	{
		next->Next			= (*head);
		next->Prev			= (*head)->Prev;

		(*head)->Prev->Next	= next;
		(*head)->Prev		= next;

		next->DllHandle = DllHandle;

		if (DllPath)
		{
			auto len = DllPath->Length;
			if (len < sizeof(MM_DEPENDENCY_RECORD::Buffer))
			{
				next->DllName.Length	= len;
				next->DllName.MaxLength	= sizeof(MM_DEPENDENCY_RECORD::Buffer);
				next->DllName.szBuffer	= next->Buffer;

				f->memmove(next->Buffer, DllPath->szBuffer, len);
			}
		}
	}

	return next;
}

__forceinline void RemoveDependencyEntry(MANUAL_MAPPING_FUNCTION_TABLE * f, MM_DEPENDENCY_RECORD * pEntry)
{
	if (pEntry)
	{
		pEntry->Next->Prev = pEntry->Prev;
		pEntry->Prev->Next = pEntry->Next;

		DeleteObject(f, pEntry);
	}
}

__forceinline MM_DEPENDENCY_RECORD * SearchDependencyRecordByHandle(MM_DEPENDENCY_RECORD * head, HANDLE hDll)
{
	if (!head)
	{
		return nullptr;
	}

	auto cur = head;

	do
	{
		if (cur->DllHandle == hDll)
		{
			return cur;
		}

		cur = cur->Next;
	} while (cur != head);

	return nullptr;
}

__forceinline void UnloadAndDeleteDependencyRecord(MANUAL_MAPPING_FUNCTION_TABLE * f, MM_DEPENDENCY_RECORD * head)
{
	if (!head)
	{
		return;
	}
	
	//unload in reverse order, won't unload everything because dependency loading is fucked since Win 1.0
	auto cur = head;

	while (true)
	{
		cur = head->Prev;

		f->LdrUnloadDll(cur->DllHandle);

		if (cur == head)
		{
			break;
		}
		else
		{
			head->Prev = cur->Prev;

			DeleteObject(f, cur);
		}
	}
}

#pragma endregion

#pragma region manual mapping internal helper functions

NTSTATUS __declspec(code_seg(".mmap_sec$11")) __stdcall MMIH_ResolveFilePath(MANUAL_MAPPING_DATA * pData, UNICODE_STRING * Module)
{
	auto f = pData->FunctionTable;

	NTSTATUS ntRet = STATUS_SUCCESS;

	if (Module->szBuffer[1] == ':')
	{
		return STATUS_SUCCESS;
	}

	wchar_t * DllSearchPath = nullptr;

	if (pData->OSVersion <= g_Win7)
	{
		DllSearchPath = f->LdrpDefaultPath->szBuffer;
	}
	else
	{
		wchar_t * Unknown = nullptr;
		ntRet = f->LdrGetDllPath(Module->szBuffer, NULL, &DllSearchPath, &Unknown);

		if (NT_FAIL(ntRet))
		{
			return ntRet;
		}
	}

	if (!DllSearchPath)
	{
		return STATUS_UNSUCCESSFUL;
	}

	auto len = SizeUnicodeString(DllSearchPath);
	if (!len)
	{
		return STATUS_UNSUCCESSFUL;
	}

	auto DllSearchPathBuffer = NewObject<wchar_t>(f, len / sizeof(wchar_t) + 1);
	if (!DllSearchPathBuffer)
	{
		return STATUS_NO_MEMORY;
	}

	f->memmove(DllSearchPathBuffer, DllSearchPath, len);

	int PathCounter = 1;
	
	for (auto i = DllSearchPathBuffer; *i; ++i)
	{
		if (*i == ';')
		{
			PathCounter++;
		}
	}

	auto DllSearchPathPointers = NewObject<wchar_t *>(f, PathCounter);
	if (!DllSearchPathPointers)
	{
		DeleteObject(f, DllSearchPathBuffer);

		return STATUS_NO_MEMORY;
	}

	PathCounter = 1;
	DllSearchPathPointers[0] = DllSearchPathBuffer;

	for (auto i = DllSearchPathBuffer; *i; ++i)
	{
		if (*i == ';')
		{
			*i = 0;
			DllSearchPathPointers[PathCounter] = i + 1;
			++PathCounter;
		}
	};

	auto * NtFilePathBuffer = NewObject<wchar_t>(f, MAX_PATH);
	if (!NtFilePathBuffer)
	{
		DeleteObject(f, DllSearchPathPointers);
		DeleteObject(f, DllSearchPathBuffer);

		return STATUS_NO_MEMORY;
	}

	auto DllNameSize = Module->Length;
	f->memmove(NtFilePathBuffer, pData->NtPathPrefix, sizeof(pData->NtPathPrefix));
	auto FilePathBuffer = NtFilePathBuffer + 4;

	IO_STATUS_BLOCK io_status{ 0 };
	auto * oa = NewObject<OBJECT_ATTRIBUTES>(f);
	if (!oa)
	{
		DeleteObject(f, NtFilePathBuffer);
		DeleteObject(f, DllSearchPathPointers);
		DeleteObject(f, DllSearchPathBuffer);

		return STATUS_NO_MEMORY;
	}

	bool file_found = false;

	for (int i = 0; i < PathCounter; ++i)
	{
		auto PathSize = SizeUnicodeString(DllSearchPathPointers[i]);
		auto FullSize = (ULONG_PTR)PathSize + (ULONG_PTR)DllNameSize + sizeof(wchar_t);
		auto NtFullSize = FullSize + sizeof(wchar_t[4]);

		if (NtFullSize > MAX_PATH * sizeof(wchar_t))
		{
			continue;
		}

		f->memmove(FilePathBuffer, DllSearchPathPointers[i], PathSize);
		FilePathBuffer[PathSize / sizeof(wchar_t)] = '\\';
		f->memmove(FilePathBuffer + PathSize / sizeof(wchar_t) + 1, Module->szBuffer, DllNameSize);
		FilePathBuffer[FullSize / sizeof(wchar_t)] = 0;

		UNICODE_STRING FilePath{ 0 };
		FilePath.Length		= SizeUnicodeString(NtFilePathBuffer);
		FilePath.MaxLength	= MAX_PATH * sizeof(wchar_t);
		FilePath.szBuffer	= NtFilePathBuffer;

		InitializeObjectAttributes(oa, &FilePath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

		HANDLE hFile = nullptr;
		ntRet = f->NtOpenFile(&hFile, SYNCHRONIZE, oa, &io_status, FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT);

		if (NT_FAIL(ntRet) || !hFile)
		{
			continue;
		}

		f->NtClose(hFile);

		f->memmove(Module->szBuffer, FilePathBuffer, FullSize);
		Module->Length = SizeUnicodeString(FilePathBuffer);
		file_found = true;

		break;
	}

	DeleteObject(f, oa);
	DeleteObject(f, NtFilePathBuffer);
	DeleteObject(f, DllSearchPathPointers);
	DeleteObject(f, DllSearchPathBuffer);

	if (file_found)
	{
		ntRet = STATUS_SUCCESS;
	}
	
	return ntRet;
}

NTSTATUS __declspec(code_seg(".mmap_sec$12")) __stdcall MMIH_PreprocessModuleName(MANUAL_MAPPING_DATA * pData, const char * szModule, UNICODE_STRING * Module, LDRP_LOAD_CONTEXT_FLAGS * CtxFlags)
{
	auto f = pData->FunctionTable;

	NTSTATUS ntRet = STATUS_SUCCESS;

	//create ANSI_STRING
	auto * ModNameA = NewObject<ANSI_STRING>(f);
	if (!ModNameA)
	{
		return STATUS_NO_MEMORY;
	}

	//move szModule into ANSI_STRING
	if (!InitAnsiString(f, ModNameA, szModule))
	{
		DeleteObject(f, ModNameA);

		return STATUS_NO_MEMORY;
	}

	//create UNICODE_STRING
	auto * ModNameW = NewObject<UNICODE_STRING>(f);
	if (!ModNameW)
	{
		DeleteObject(f, ModNameA->szBuffer);
		DeleteObject(f, ModNameA);

		return STATUS_NO_MEMORY;
	}

	//allocate buffer for UNICODE_STRING
	ModNameW->szBuffer	= NewObject<wchar_t>(f, MAX_PATH);
	ModNameW->MaxLength = sizeof(wchar_t[MAX_PATH]);

	if (!ModNameW->szBuffer)
	{
		DeleteObject(f, ModNameW);
		DeleteObject(f, ModNameA->szBuffer);
		DeleteObject(f, ModNameA);

		return STATUS_NO_MEMORY;
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

	//Win10+ needs LdrpPreprocessDllName
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

		ntRet = f->LdrpPreprocessDllName(ModNameW, pModPathW, nullptr, CtxFlags);

		if (NT_SUCCESS(ntRet))
		{
			//copy preprocessed dll name and create new buffer
			Module->Length		= pModPathW->String.Length;
			Module->MaxLength	= pModPathW->String.MaxLength;
			Module->szBuffer	= NewObject<wchar_t>(f, Module->MaxLength / sizeof(wchar_t));

			if (!Module->szBuffer)
			{
				DeleteObject(f, pModPathW);
				DeleteObject(f, ModNameW->szBuffer);
				DeleteObject(f, ModNameW);

				return STATUS_NO_MEMORY;
			}
			else
			{
				f->memmove(Module->szBuffer, pModPathW->StaticBuffer, Module->Length);
			}
		}
		else
		{
			DeleteObject(f, pModPathW);
			DeleteObject(f, ModNameW->szBuffer);
			DeleteObject(f, ModNameW);

			return ntRet;
		}
	}
	else
	{
		//don't create new buffer
		Module->Length		= ModNameW->Length;
		Module->MaxLength	= ModNameW->MaxLength;
		Module->szBuffer	= ModNameW->szBuffer;
	}

	DeleteObject(f, ModNameW);

	return STATUS_SUCCESS;
}

NTSTATUS __declspec(code_seg(".mmap_sec$13")) __stdcall MMIH_LoadModule(MANUAL_MAPPING_DATA * pData, UNICODE_STRING * Module, LDRP_LOAD_CONTEXT_FLAGS CtxFlag, HINSTANCE * hModule, MM_DEPENDENCY_RECORD ** head)
{
	//load module using LdrpLoadDll(Internal)
	//function protoype is heavily platform dependent

	auto f = pData->FunctionTable;

	NTSTATUS ntRet = STATUS_SUCCESS;

	LDR_DATA_TABLE_ENTRY * entry_out = nullptr;

	if (pData->OSVersion >= g_Win10)
	{
		auto * ctx = NewObject<LDRP_PATH_SEARCH_CONTEXT>(f);
		if (!ctx)
		{
			return STATUS_NO_MEMORY;
		}

		if (pData->OSBuildNumber == g_Win10_1511)
		{
			ReCa<LDRP_PATH_SEARCH_CONTEXT_1511 *>(ctx)->OriginalFullDllName = Module->szBuffer;
		}
		else
		{
			ctx->OriginalFullDllName = Module->szBuffer;
		}

		if (pData->OSBuildNumber >= g_Win11_21H2)
		{
			auto _LdrpLoadDllInternal = ReCa<f_LdrpLoadDllInternal_WIN11>(f->LdrpLoadDllInternal);
			_LdrpLoadDllInternal(Module, ctx, CtxFlag, 4, nullptr, nullptr, ReCa<LDR_DATA_TABLE_ENTRY_WIN11 **>(&entry_out), &ntRet, 0);
		}
		else
		{
			f->LdrpLoadDllInternal(Module, ctx, CtxFlag, 4, nullptr, nullptr, ReCa<LDR_DATA_TABLE_ENTRY_WIN10 **>(&entry_out), &ntRet);
		}

		DeleteObject(f, ctx);
	}
	else if (pData->OSVersion == g_Win81)
	{
		auto * ctx = NewObject<LDRP_PATH_SEARCH_CONTEXT_WIN81>(f);
		if (!ctx)
		{
			return STATUS_NO_MEMORY;
		}
		
		ctx->OriginalFullDllName = Module->szBuffer;

		LDR_DDAG_NODE_WIN81 * ddag_out = nullptr;

		auto _LdrpLoadDll = ReCa<f_LdrpLoadDll_WIN81>(f->LdrpLoadDll);
		ntRet = _LdrpLoadDll(Module, ctx, CtxFlag, TRUE, ReCa<LDR_DATA_TABLE_ENTRY_WIN81 **>(&entry_out), &ddag_out);

		DeleteObject(f, ctx);
	}
	else if (pData->OSVersion == g_Win8)
	{
		auto * ctx = NewObject<LDRP_PATH_SEARCH_CONTEXT_WIN8>(f);
		if (!ctx)
		{
			return STATUS_NO_MEMORY;
		}

		ctx->OriginalFullDllName = Module->szBuffer;
		ctx->unknown2 = TRUE;

		LDR_DDAG_NODE_WIN8 * ddag_out = nullptr;

		auto _LdrpLoadDll = ReCa<f_LdrpLoadDll_WIN8>(f->LdrpLoadDll);
		ntRet = _LdrpLoadDll(Module, ctx, CtxFlag, TRUE, ReCa<LDR_DATA_TABLE_ENTRY_WIN8 **>(&entry_out), &ddag_out);

		DeleteObject(f, ctx);
	}
	else if (pData->OSVersion == g_Win7)
	{
		auto _LdrpLoadDll = ReCa<f_LdrpLoadDll_WIN7>(f->LdrpLoadDll);
		ntRet = _LdrpLoadDll(Module, f->LdrpDefaultPath, CtxFlag, TRUE, nullptr, ReCa<LDR_DATA_TABLE_ENTRY_WIN7 **>(&entry_out));
	}
	else
	{
		ntRet = STATUS_NOT_IMPLEMENTED;
	}
	
	if (NT_SUCCESS(ntRet))
	{
		if (entry_out)
		{
			*hModule = ReCa<HINSTANCE>(entry_out->DllBase);

			MM_DEPENDENCY_RECORD * entry = nullptr;

			if (head)
			{
				entry = SearchDependencyRecordByHandle(*head, entry_out->DllBase);
			}

			if (!entry)
			{
				entry = BuildDependencyRecord(f, head, ReCa<HANDLE>(*hModule), &entry_out->FullDllName);
			}

			if (pData->OSVersion >= g_Win10)
			{
				f->LdrpDereferenceModule(entry_out);
			}
		}
		else
		{
			ntRet = STATUS_DLL_NOT_FOUND;
		}
	}

	return ntRet;
}

#pragma endregion

DWORD __declspec(code_seg(".mmap_sec$01")) __stdcall ManualMapping_Shell(MANUAL_MAPPING_DATA * pData)
{
	if (!pData)
	{
		return INJ_MM_ERR_NO_DATA;
	}

	pData->DllPath.szBuffer = pData->szPathBuffer;

	//grab LdrpHeap pointer
	auto * f = pData->FunctionTable;
	if (!f->pLdrpHeap)
	{
		f->pLdrpHeap = *f->LdrpHeap;
	}

	if (!f->pLdrpHeap)
	{
		return INJ_MM_ERR_INVALID_HEAP_HANDLE;
	}

	auto ret = f->MMIP_MapSections(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	ret = f->MMIP_RelocateImage(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	ret = f->MMIP_InitializeCookie(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}
	
	ret = f->MMIP_LoadImports(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	ret = f->MMIP_LoadDelayImports(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	ret = f->MMIP_SetPageProtections(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	ret = f->MMIP_EnableExceptions(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	ret = f->MMIP_HandleTLS(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	ret = f->MMIP_ExecuteDllMain(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}
		
	//ignore cloaking return values since the module is loaded and executed already
	f->MMIP_CleanDataDirectories(pData);
	f->MMIP_CloakHeader(pData);

	//unlock file
	if (pData->hDllFile)
	{
		f->NtClose(pData->hDllFile);
	}

	//grab image base
	pData->hRet = ReCa<HINSTANCE>(pData->pImageBase);

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$02")) __stdcall MMI_MapSections(MANUAL_MAPPING_DATA * pData)
{
	auto f = pData->FunctionTable;

	if (!(pData->Flags & INJ_MM_MAP_FROM_MEMORY))
	{
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

		//update string buffer addresse
		UNICODE_STRING DllPath = pData->DllPath;
		DllPath.szBuffer = pData->szPathBuffer;

		auto * oa = NewObject<OBJECT_ATTRIBUTES>(f);
		if (!oa)
		{
			DeleteObject(f, DllNtPath.szBuffer);

			return INJ_MM_ERR_HEAP_ALLOC;
		}

		InitializeObjectAttributes(oa, &DllNtPath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

		IO_STATUS_BLOCK io_status{ 0 };

		//open dll file
		pData->ntRet = f->NtOpenFile(&pData->hDllFile, FILE_GENERIC_READ, oa, &io_status, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

		DeleteObject(f, oa);
		DeleteObject(f, DllNtPath.szBuffer);

		if (NT_FAIL(pData->ntRet))
		{
			return INJ_MM_ERR_NT_OPEN_FILE;
		}

		auto * fsi = NewObject<FILE_STANDARD_INFO>(f);
		if (!fsi)
		{
			return INJ_MM_ERR_HEAP_ALLOC;
		}

		//query basic file information
		pData->ntRet = f->NtQueryInformationFile(pData->hDllFile, &io_status, fsi, sizeof(FILE_STANDARD_INFO), FILE_INFORMATION_CLASS::FileStandardInformation);
		if (NT_FAIL(pData->ntRet))
		{
			DeleteObject(f, fsi);

			return INJ_MM_ERR_CANT_GET_FILE_SIZE;
		}

		SIZE_T RawSize = fsi->AllocationSize.LowPart;

		//allocate memory for the raw dll file
		pData->ntRet = f->NtAllocateVirtualMemory(NtCurrentProcess(), ReCa<void **>(&pData->pRawData), 0, &RawSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (NT_FAIL(pData->ntRet))
		{
			DeleteObject(f, fsi);

			return INJ_MM_ERR_MEMORY_ALLOCATION_FAILED;
		}

		auto * pos = NewObject<FILE_POSITION_INFORMATION>(f);
		if (!pos)
		{
			DeleteObject(f, fsi);

			return INJ_MM_ERR_HEAP_ALLOC;
		}

		//reset file pointer
		pData->ntRet = f->NtSetInformationFile(pData->hDllFile, &io_status, pos, sizeof(FILE_POSITION_INFORMATION), FILE_INFORMATION_CLASS::FilePositionInformation);
		if (NT_FAIL(pData->ntRet))
		{
			DeleteObject(f, fsi);

			return INJ_MM_ERR_SET_FILE_POSITION;
		}

		DeleteObject(f, pos);

		//read raw dll file into memory
		pData->ntRet = f->NtReadFile(pData->hDllFile, nullptr, nullptr, nullptr, &io_status, pData->pRawData, fsi->AllocationSize.LowPart, nullptr, nullptr);
		if (NT_FAIL(pData->ntRet))
		{
			DeleteObject(f, fsi);

			return INJ_MM_ERR_NT_READ_FILE;
		}

		DeleteObject(f, fsi);
	}
	
	//grab pe header pointers (assuming the file is a valid dll)
	pData->pDosHeader		= ReCa<IMAGE_DOS_HEADER *>(pData->pRawData);
	pData->pNtHeaders		= ReCa<IMAGE_NT_HEADERS *>(pData->pRawData + pData->pDosHeader->e_lfanew);
	pData->pOptionalHeader	= &pData->pNtHeaders->OptionalHeader;
	pData->pFileHeader		= &pData->pNtHeaders->FileHeader;

	SIZE_T ImgSize = static_cast<SIZE_T>(pData->pOptionalHeader->SizeOfImage);

	//update allocation size depending on flags
	if (pData->Flags & INJ_MM_SHIFT_MODULE_BASE && !(pData->Flags & INJ_MM_SET_PAGE_PROTECTIONS))
	{
		ImgSize += pData->ShiftOffset;
	}

	if (pData->Flags & INJ_MM_ENABLE_EXCEPTIONS)
	{
		//allocate additional memory for the VEH shell/data
		ImgSize += ALIGN_UP(pData->VEHShellSize + sizeof(VEH_SHELL_DATA) + 0x10, 0x1000);
	}

	//allocate memory for the dll
	pData->ntRet = f->NtAllocateVirtualMemory(NtCurrentProcess(), ReCa<void **>(&pData->pAllocationBase), 0, &ImgSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (NT_FAIL(pData->ntRet))
	{
		return INJ_MM_ERR_MEMORY_ALLOCATION_FAILED;
	}

	//update pointers depending on flags
	if (pData->Flags & INJ_MM_SHIFT_MODULE_BASE && !(pData->Flags & INJ_MM_SET_PAGE_PROTECTIONS))
	{
		pData->pImageBase = pData->pAllocationBase + pData->ShiftOffset;
	}
	else
	{
		pData->pImageBase = pData->pAllocationBase;
	}

	//copy header and sections
	f->memmove(pData->pImageBase, pData->pRawData, pData->pOptionalHeader->SizeOfHeaders);

	auto * pCurrentSectionHeader = IMAGE_FIRST_SECTION(pData->pNtHeaders);
	for (UINT i = 0; i != pData->pFileHeader->NumberOfSections; ++i, ++pCurrentSectionHeader)
	{
		if (pCurrentSectionHeader->SizeOfRawData)
		{
			f->memmove(pData->pImageBase + pCurrentSectionHeader->VirtualAddress, pData->pRawData + pCurrentSectionHeader->PointerToRawData, pCurrentSectionHeader->SizeOfRawData);
		}
	}

	if (!(pData->Flags & INJ_MM_MAP_FROM_MEMORY))
	{
		//remove raw data
		SIZE_T RawSize = 0;
		f->NtFreeVirtualMemory(NtCurrentProcess(), ReCa<void **>(&pData->pRawData), &RawSize, MEM_RELEASE);
		pData->pRawData = nullptr;
	}	
	
	//update pe headers to the new location
	pData->pDosHeader		= ReCa<IMAGE_DOS_HEADER *>(pData->pImageBase);
	pData->pNtHeaders		= ReCa<IMAGE_NT_HEADERS *>(pData->pImageBase + pData->pDosHeader->e_lfanew);
	pData->pOptionalHeader	= &pData->pNtHeaders->OptionalHeader;
	pData->pFileHeader		= &pData->pNtHeaders->FileHeader;

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$03")) __stdcall MMI_RelocateImage(MANUAL_MAPPING_DATA * pData)
{
	BYTE * LocationDelta = pData->pImageBase - pData->pOptionalHeader->ImageBase;

	//relocate the image if necessary
	if (LocationDelta)
	{
		auto * pRelocDir = ReCa<IMAGE_DATA_DIRECTORY *>(&pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

		if (!pRelocDir->Size)
		{
			return INJ_MM_ERR_IMAGE_CANT_BE_RELOCATED;
		}

		auto * pRelocData = ReCa<IMAGE_BASE_RELOCATION *>(pData->pImageBase + pRelocDir->VirtualAddress);

		while (pRelocData->VirtualAddress)
		{
			WORD * pRelativeInfo = ReCa<WORD *>(pRelocData + 1);
			UINT RelocCount = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			for (UINT i = 0; i < RelocCount; ++i, ++pRelativeInfo)
			{
				if (RELOC_FLAG(*pRelativeInfo))
				{
					ULONG_PTR * pPatch = ReCa<ULONG_PTR *>(pData->pImageBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
					*pPatch += ReCa<ULONG_PTR>(LocationDelta);
				}
			}

			pRelocData = ReCa<IMAGE_BASE_RELOCATION *>(ReCa<BYTE *>(pRelocData) + pRelocData->SizeOfBlock);

			if (pRelocData >= ReCa<IMAGE_BASE_RELOCATION *>(pData->pImageBase + pRelocDir->VirtualAddress + pRelocDir->Size))
			{
				break;
			}
		}

		pData->pOptionalHeader->ImageBase += ReCa<ULONG_PTR>(LocationDelta);
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$04")) __stdcall MMI_InitializeCookie(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_MM_INIT_SECURITY_COOKIE) || !pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size)
	{
		//technically not good but what u gonna do about it

		return INJ_ERR_SUCCESS;
	}

#ifdef _WIN64
	ULONGLONG new_cookie = ((UINT_PTR)pData->pImageBase) & 0x0000FFFFFFFFFFFF;
	if (new_cookie == 0x2B992DDFA232)
	{
		++new_cookie;
	}
	else if (!(new_cookie & 0x0000FFFF00000000))
	{
		new_cookie |= (new_cookie | 0x4711) << 0x10;
	}
#else
	DWORD new_cookie = (UINT_PTR)pData->pImageBase;
	if (new_cookie == 0xBB40E64E)
	{
		++new_cookie;
	}
	else if (!(new_cookie & 0xFFFF0000))
	{
		new_cookie |= (new_cookie | 0x4711) << 16;
	}
#endif

	auto pLoadConfigData = ReCa<IMAGE_LOAD_CONFIG_DIRECTORY *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
	pLoadConfigData->SecurityCookie = new_cookie;

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$06")) __stdcall MMI_LoadImports(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & (INJ_MM_RESOLVE_IMPORTS | INJ_MM_RUN_DLL_MAIN)))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	NTSTATUS ntRet = STATUS_SUCCESS;

	IMAGE_DATA_DIRECTORY	* pImportDir	= ReCa<IMAGE_DATA_DIRECTORY *>(&pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	IMAGE_IMPORT_DESCRIPTOR * pImportDescr	= nullptr;

	if (pImportDir->Size)
	{
		pImportDescr = ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pImportDir->VirtualAddress);
	}

	bool ErrorBreak = false;

	while (pImportDescr && pImportDescr->Name)
	{
		//grab import name
		auto * szModule = ReCa<const char *>(pData->pImageBase + pImportDescr->Name);

		UNICODE_STRING ModNameW{ 0 };

		ModNameW.MaxLength	= MAX_PATH * sizeof(wchar_t);
		ModNameW.szBuffer	= NewObject<wchar_t>(f, MAX_PATH);
		if (!ModNameW.szBuffer)
		{
			ntRet = STATUS_NO_MEMORY;

			ErrorBreak = true;
			break;
		}

		LDRP_LOAD_CONTEXT_FLAGS ctx_flags{ 0 };
		ntRet = f->MMIHP_PreprocessModuleName(pData, szModule, &ModNameW, &ctx_flags);
		if (NT_FAIL(ntRet))
		{
			DeleteObject(f, ModNameW.szBuffer);

			if (ntRet == STATUS_APISET_NOT_HOSTED)
			{
				++pImportDescr;

				if (pImportDescr >= ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pImportDir->VirtualAddress + pImportDir->Size))
				{
					break;
				}

				continue;
			}

			ErrorBreak = true;
			break;
		}


		bool is_path = false;

		UNICODE_STRING ModNameW2 = ModNameW;
		//check if preprocess returned full path, maybe use ctx_flags for this?
		if (ModNameW.szBuffer[1] == ':')
		{
			is_path = true;

			auto * end = ModNameW2.szBuffer + ModNameW2.Length / sizeof(wchar_t);
			while (*(end - 1) != '\\')
			{
				--end;
			}

			ModNameW2.szBuffer	= end;
			ModNameW2.Length	= ModNameW.Length - (WORD)(sizeof(wchar_t) * (end - ModNameW.szBuffer));
			ModNameW2.MaxLength -= ModNameW.Length - ModNameW2.Length;
		}

		//load import
		HINSTANCE hDll = NULL;

		pData->ntRet = f->MMIHP_LoadModule(pData, &ModNameW, ctx_flags, &hDll, &pData->pImportsHead);
		
		if (NT_FAIL(pData->ntRet))
		{
			DeleteObject(f, ModNameW.szBuffer);

			if (pData->ntRet == STATUS_APISET_NOT_HOSTED)
			{
				++pImportDescr;

				if (pImportDescr >= ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pImportDir->VirtualAddress + pImportDir->Size))
				{
					break;
				}

				continue;
			}

			//unable to load required library
			ErrorBreak = true;
			break;
		}

		//grab import data
		IMAGE_THUNK_DATA * pThunk	= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pImportDescr->OriginalFirstThunk);
		IMAGE_THUNK_DATA * pIAT		= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pImportDescr->FirstThunk);

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

				pData->ntRet = f->LdrGetProcedureAddress(ReCa<void *>(hDll), nullptr, IMAGE_ORDINAL(pThunk->u1.Ordinal), ReCa<void **>(pFuncRef));
			}
			else
			{
				//by name

				pImport = ReCa<IMAGE_IMPORT_BY_NAME *>(pData->pImageBase + (pThunk->u1.AddressOfData));

				//convert c string import into ANSI_STRING
				auto * ansi_import = NewObject<ANSI_STRING>(f);
				if (!ansi_import)
				{
					ErrorBreak = true;
					break;
				}

				ansi_import->szBuffer	= pImport->Name;
				ansi_import->Length		= SizeAnsiString(ansi_import->szBuffer);
				ansi_import->MaxLength	= ansi_import->Length + 1 * sizeof(char);

				//load imported function address and save to IAT

				pData->ntRet = f->LdrGetProcedureAddress(ReCa<void *>(hDll), ansi_import, 0, ReCa<void **>(pFuncRef));

				DeleteObject(f, ansi_import);
			}

			if (NT_FAIL(pData->ntRet))
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
		if (pImportDescr >= ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pImportDir->VirtualAddress + pImportDir->Size))
		{
			break;
		}
	}

	if (ErrorBreak)
	{
		return INJ_MM_ERR_IMPORT_FAIL;
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$07")) __stdcall MMI_LoadDelayImports(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_MM_RESOLVE_DELAY_IMPORTS))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	NTSTATUS ntRet = STATUS_SUCCESS;

	IMAGE_DATA_DIRECTORY		* pDelayImportDir	= ReCa<IMAGE_DATA_DIRECTORY *>(&pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]);
	IMAGE_DELAYLOAD_DESCRIPTOR	* pDelayImportDescr = nullptr;

	if (pDelayImportDir->Size)
	{
		pDelayImportDescr = ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pDelayImportDir->VirtualAddress);
	}

	bool ErrorBreak = false;

	while (pDelayImportDescr && pDelayImportDescr->DllNameRVA)
	{
		auto * szModule = ReCa<const char *>(pData->pImageBase + pDelayImportDescr->DllNameRVA);
		
		UNICODE_STRING ModNameW{ 0 };

		ModNameW.MaxLength	= MAX_PATH * sizeof(wchar_t);
		ModNameW.szBuffer	= NewObject<wchar_t>(f, MAX_PATH);
		if (!ModNameW.szBuffer)
		{
			ntRet = STATUS_NO_MEMORY;

			ErrorBreak = true;
			break;
		}

		LDRP_LOAD_CONTEXT_FLAGS ctx_flags{ 0 };
		ntRet = f->MMIHP_PreprocessModuleName(pData, szModule, &ModNameW, &ctx_flags);
		if (NT_FAIL(ntRet))
		{
			DeleteObject(f, ModNameW.szBuffer);

			if (ntRet == STATUS_APISET_NOT_HOSTED)
			{
				++pDelayImportDescr;

				if (pDelayImportDescr >= ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pDelayImportDir->VirtualAddress + pDelayImportDir->Size))
				{
					break;
				}

				continue;
			}

			ErrorBreak = true;
			break;
		}

		bool is_path = false;

		UNICODE_STRING ModNameW2 = ModNameW;
		if (ModNameW.szBuffer[1] == ':')
		{
			is_path = true;

			auto * end = ModNameW2.szBuffer + ModNameW2.Length / sizeof(wchar_t);
			while (*(end - 1) != '\\')
			{
				--end;
			}

			ModNameW2.szBuffer	= end;
			ModNameW2.Length	= ModNameW.Length - (WORD)(sizeof(wchar_t) * (end - ModNameW.szBuffer));
			ModNameW2.MaxLength -= ModNameW.Length - ModNameW2.Length;
		}

		HINSTANCE hDll = NULL;

		pData->ntRet = f->MMIHP_LoadModule(pData, &ModNameW, ctx_flags, &hDll, &pData->pImportsHead);
		
		if (NT_FAIL(pData->ntRet))
		{
			DeleteObject(f, ModNameW.szBuffer);

			if (pData->ntRet == STATUS_APISET_NOT_HOSTED)
			{
				++pDelayImportDescr;

				if (pDelayImportDescr >= ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pDelayImportDir->VirtualAddress + pDelayImportDir->Size))
				{
					break;
				}

				continue;
			}

			ErrorBreak = true;
			break;
		}

		DeleteObject(f, ModNameW.szBuffer);

		if (pDelayImportDescr->ModuleHandleRVA)
		{
			HINSTANCE * pModule = ReCa<HINSTANCE *>(pData->pImageBase + pDelayImportDescr->ModuleHandleRVA);
			*pModule = hDll;
		}

		IMAGE_THUNK_DATA * pIAT			= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pDelayImportDescr->ImportAddressTableRVA);
		IMAGE_THUNK_DATA * pNameTable	= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pDelayImportDescr->ImportNameTableRVA);

		for (; pIAT->u1.Function; ++pIAT, ++pNameTable)
		{
			if (IMAGE_SNAP_BY_ORDINAL(pNameTable->u1.Ordinal))
			{
				pData->ntRet = f->LdrGetProcedureAddress(ReCa<void *>(hDll), nullptr, IMAGE_ORDINAL(pNameTable->u1.Ordinal), ReCa<void **>(pIAT));
			}
			else
			{
				auto pImport = ReCa<IMAGE_IMPORT_BY_NAME *>(pData->pImageBase + (pNameTable->u1.AddressOfData));

				auto * ansi_import= NewObject<ANSI_STRING>(f);
				if (!ansi_import)
				{
					ErrorBreak = true;
					break;
				}

				ansi_import->szBuffer	= pImport->Name;
				ansi_import->Length		= SizeAnsiString(ansi_import->szBuffer);
				ansi_import->MaxLength	= ansi_import->Length + 1 * sizeof(char);

				pData->ntRet = f->LdrGetProcedureAddress(ReCa<void *>(hDll), ansi_import, IMAGE_ORDINAL(pNameTable->u1.Ordinal), ReCa<void **>(pIAT));
			}

			if (NT_FAIL(pData->ntRet))
			{
				ErrorBreak = true;
				break;
			}
		}

		++pDelayImportDescr;

		if (pDelayImportDescr >= ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pDelayImportDir->VirtualAddress + pDelayImportDir->Size))
		{
			break;
		}
	}

	if (ErrorBreak)
	{
		return INJ_MM_ERR_DELAY_IMPORT_FAIL;
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$08")) __stdcall MMI_SetPageProtections(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_MM_SET_PAGE_PROTECTIONS))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	ULONG OldProtection = 0;
	SIZE_T SizeOut = pData->pOptionalHeader->SizeOfHeaders;
	pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), ReCa<void **>(&pData->pImageBase), &SizeOut, PAGE_EXECUTE_READ, &OldProtection);

	if (NT_FAIL(pData->ntRet))
	{
		return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
	}

	//iterate over all the previously mapped sections
	auto pCurrentSectionHeader = IMAGE_FIRST_SECTION(pData->pNtHeaders);

	for (UINT i = 0; i != pData->pFileHeader->NumberOfSections; ++i, ++pCurrentSectionHeader)
	{
		void * pSectionBase		= pData->pImageBase + pCurrentSectionHeader->VirtualAddress;
		DWORD characteristics	= pCurrentSectionHeader->Characteristics;
		SIZE_T SectionSize		= pCurrentSectionHeader->SizeOfRawData;

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
			pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &pSectionBase, &SectionSize, NewProtection, &OldProtection);
			if (NT_FAIL(pData->ntRet))
			{
				break;
			}
		}
	}

	if (NT_FAIL(pData->ntRet))
	{
		return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$09")) __stdcall MMI_EnableExceptions(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_MM_ENABLE_EXCEPTIONS))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	pData->pVEHShellMapped	= pData->pImageBase + pData->pOptionalHeader->SizeOfImage;
	pData->pVEHShellData	= ReCa<VEH_SHELL_DATA *>(ALIGN_UP(pData->pVEHShellMapped + pData->VEHShellSize, 0x10));

	bool veh_shell_fixed = false;
	
	//set up veh data structure
	pData->pVEHShellData->ImgBase	= ReCa<ULONG_PTR>(pData->pImageBase);
	pData->pVEHShellData->ImgSize	= pData->pOptionalHeader->SizeOfImage;
	pData->pVEHShellData->OSVersion	= pData->OSVersion;
		
	pData->pVEHShellData->LdrpInvertedFunctionTable	= f->LdrpInvertedFunctionTable;
	pData->pVEHShellData->LdrProtectMrdata			= f->LdrProtectMrdata;

	f->memmove(pData->pVEHShellMapped, pData->pVEHShell, pData->VEHShellSize);

	//insert veh data structure pointer into mapped veh shell
	veh_shell_fixed = FindAndReplacePtr(pData->pVEHShellMapped, pData->VEHShellSize, VEHDATASIG, ReCa<UINT_PTR>(pData->pVEHShellData));

	//try RtlInsertInvertedFunctionTable first
	if (pData->OSVersion >= g_Win81)
	{
		f->RtlInsertInvertedFunctionTable(pData->pImageBase, pData->pOptionalHeader->SizeOfImage);
	}
	else if (pData->OSVersion == g_Win8)
	{
		auto _RtlInsertInvertedFunctionTable = ReCa<f_RtlInsertInvertedFunctionTable_WIN8>(f->RtlInsertInvertedFunctionTable);
		_RtlInsertInvertedFunctionTable(pData->pImageBase, pData->pOptionalHeader->SizeOfImage);
	}
	else if (pData->OSVersion == g_Win7)
	{
		auto _RtlInsertInvertedFunctionTable = ReCa<f_RtlInsertInvertedFunctionTable_WIN7>(f->RtlInsertInvertedFunctionTable);
		_RtlInsertInvertedFunctionTable(ReCa<RTL_INVERTED_FUNCTION_TABLE_WIN7 *>(f->LdrpInvertedFunctionTable), pData->pImageBase, pData->pOptionalHeader->SizeOfImage);
	}

	pData->ntRet = STATUS_DLL_NOT_FOUND;
	bool partial = true;

#ifdef _WIN64
	if (veh_shell_fixed)
	{
		//register VEH shell to fill SEH handler list
		pData->hVEH = f->RtlAddVectoredExceptionHandler(0, ReCa<PVECTORED_EXCEPTION_HANDLER>(pData->pVEHShellMapped));
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

		if (entry->ImageBase != pData->pImageBase)
		{
			continue;
		}

		if (entry->ExceptionDirectorySize)
		{
			//module exists, entries have been initialized
			partial = false;
			pData->ntRet = STATUS_SUCCESS;

			break;
		}

		//module exists, entries don't
		//create fake entry which will be filled at runtime using a VEH shell
		SIZE_T FakeDirSize = 0x800 * sizeof(void *);
		pData->ntRet = f->NtAllocateVirtualMemory(NtCurrentProcess(), &pData->pFakeSEHDirectory, 0, &FakeDirSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (NT_FAIL(pData->ntRet))
		{
			break;
		}

		//EncodeSystemPointer
		UINT_PTR pRaw = ReCa<UINT_PTR>(pData->pFakeSEHDirectory);
		auto cookie = *P_KUSER_SHARED_DATA_COOKIE;

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
			pData->hVEH = f->RtlAddVectoredExceptionHandler(0, ReCa<PVECTORED_EXCEPTION_HANDLER>(pData->pVEHShellMapped));
		}

		break;
	}

#ifdef _WIN64
	if (NT_SUCCESS(pData->ntRet) && partial)
	{
		//on x64 also try documented method
		auto size = pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
		if (size)
		{
			auto * pExceptionHandlers = ReCa<RUNTIME_FUNCTION *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
			auto EntryCount = size / sizeof(RUNTIME_FUNCTION);

			if (!f->RtlAddFunctionTable(pExceptionHandlers, MDWD(EntryCount), ReCa<DWORD64>(pData->pImageBase)))
			{
				pData->ntRet = STATUS_UNSUCCESSFUL;
			}
		}
		else
		{
			pData->ntRet = STATUS_UNSUCCESSFUL;
		}
	}
#endif

	if (NT_FAIL(pData->ntRet))
	{
		return INJ_MM_ERR_ENABLING_SEH_FAILED;
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$0A")) __stdcall MMI_HandleTLS(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_MM_EXECUTE_TLS))
	{
		return INJ_ERR_SUCCESS;
	}

	if (!pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	auto * pTLS = ReCa<IMAGE_TLS_DIRECTORY *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

	auto * pDummyLdr = NewObject<LDR_DATA_TABLE_ENTRY>(f);
	if (!pDummyLdr)
	{
		return INJ_MM_ERR_HEAP_ALLOC;
	}

	//LdrpHandleTlsData either crashes or returns STATUS_SUCCESS -> no point in error checking
	//it also only accesses the DllBase member of the ldr entry thus a dummy ldr entry is sufficient

	pDummyLdr->DllBase = pData->pImageBase;

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

	//iterate through and call TLS callbacks
	auto * pCallback = ReCa<PIMAGE_TLS_CALLBACK *>(pTLS->AddressOfCallBacks);
	for (; pCallback && (*pCallback); ++pCallback)
	{
		auto Callback = *pCallback;
		Callback(pData->pImageBase, DLL_PROCESS_ATTACH, nullptr);
	}

	//unlink from tls list so the dummy ldr entry can be released
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

	//delete the dummy ldr entry
	DeleteObject(f, pDummyLdr);

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$0B")) __stdcall MMI_ExecuteDllMain(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_MM_RUN_DLL_MAIN))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	if (!pData->pOptionalHeader->AddressOfEntryPoint)
	{
		return INJ_ERR_SUCCESS;
	}

	ULONG		State	= 0;
	ULONG_PTR	Cookie	= 0;
	bool		locked	= false;

	if (pData->Flags & INJ_MM_RUN_UNDER_LDR_LOCK)
	{
		pData->ntRet = f->LdrLockLoaderLock(NULL, &State, &Cookie);

		//don't interrupt only because loader lock wasn't acquired
		locked = NT_SUCCESS(pData->ntRet);
	}

	f_DLL_ENTRY_POINT DllMain = ReCa<f_DLL_ENTRY_POINT>(pData->pImageBase + pData->pOptionalHeader->AddressOfEntryPoint);
	DllMain(ReCa<HINSTANCE>(pData->pImageBase), DLL_PROCESS_ATTACH, nullptr);

	if ((pData->Flags & INJ_MM_RUN_UNDER_LDR_LOCK) && locked)
	{
		f->LdrUnlockLoaderLock(NULL, Cookie);
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$0C")) __stdcall MMI_CleanDataDirectories(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_MM_CLEAN_DATA_DIR && !(pData->Flags & INJ_MM_SET_PAGE_PROTECTIONS)))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	//remove strings from the import directory
	DWORD Size = pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	if (Size)
	{
		auto * pImportDescr = ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name)
		{
			char * szMod = ReCa<char *>(pData->pImageBase + pImportDescr->Name);
			for (; *szMod++; *szMod = '\0');
			pImportDescr->Name = 0;

			IMAGE_THUNK_DATA * pThunk	= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pImportDescr->OriginalFirstThunk);
			IMAGE_THUNK_DATA * pIAT		= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pImportDescr->FirstThunk);

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
					auto * pImport	= ReCa<IMAGE_IMPORT_BY_NAME *>(pData->pImageBase + (pThunk->u1.AddressOfData));
					char * szFunc	= pImport->Name;
					for (; *szFunc++; *szFunc = '\0');
				}
			}

			pImportDescr->OriginalFirstThunk = 0;
			pImportDescr->FirstThunk = 0;

			++pImportDescr;
		}

		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;
	}

	//remove strings from the delay import directory
	Size = pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size;
	if (Size && !(pData->Flags & INJ_MM_RESOLVE_DELAY_IMPORTS))
	{
		auto * pDelayImportDescr = ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);

		while (pDelayImportDescr->DllNameRVA)
		{
			char * szMod = ReCa<char *>(pData->pImageBase + pDelayImportDescr->DllNameRVA);
			for (; *szMod++; *szMod = '\0');
			pDelayImportDescr->DllNameRVA = 0;

			pDelayImportDescr->ModuleHandleRVA = 0;

			IMAGE_THUNK_DATA * pIAT			= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pDelayImportDescr->ImportAddressTableRVA);
			IMAGE_THUNK_DATA * pNameTable	= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pDelayImportDescr->ImportNameTableRVA);

			for (; pIAT->u1.Function; ++pIAT, ++pNameTable)
			{

				if (IMAGE_SNAP_BY_ORDINAL(pNameTable->u1.Ordinal))
				{
					pNameTable->u1.Ordinal = 0;
				}
				else
				{
					auto * pImport	= ReCa<IMAGE_IMPORT_BY_NAME *>(pData->pImageBase + (pNameTable->u1.AddressOfData));
					char * szFunc	= pImport->Name;
					for (; (*szFunc)++; *szFunc = '\0');
				}
			}

			pDelayImportDescr->ImportAddressTableRVA = 0;
			pDelayImportDescr->ImportNameTableRVA = 0;

			++pDelayImportDescr;
		}

		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress = 0;
		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size = 0;
	}

	//remove debug data
	Size = pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
	if (Size)
	{
		auto * pDebugDir = ReCa<IMAGE_DEBUG_DIRECTORY *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);

		BYTE * pDebugData = pData->pImageBase + pDebugDir->AddressOfRawData;
		f->RtlZeroMemory(pDebugData, pDebugDir->SizeOfData);

		pDebugDir->SizeOfData = 0;
		pDebugDir->AddressOfRawData = 0;
		pDebugDir->PointerToRawData = 0;

		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
	}

	//remove base relocation information
	Size = pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	if (Size)
	{
		auto * pRelocData = ReCa<IMAGE_BASE_RELOCATION *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pRelocData->VirtualAddress)
		{
			WORD * pRelativeInfo = ReCa<WORD *>(pRelocData + 1);
			UINT RelocCount = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION));

			f->RtlZeroMemory(pRelativeInfo, RelocCount);

			pRelocData = ReCa<IMAGE_BASE_RELOCATION *>(ReCa<BYTE *>(pRelocData) + pRelocData->SizeOfBlock);
		}

		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
	}

	//remove TLS callback information
	Size = pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
	if (Size)
	{
		auto * pTLS			= ReCa<IMAGE_TLS_DIRECTORY *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto * pCallback	= ReCa<PIMAGE_TLS_CALLBACK *>(pTLS->AddressOfCallBacks);
		for (; pCallback && (*pCallback); ++pCallback)
		{
			*pCallback = nullptr;
		}

		pTLS->AddressOfCallBacks	= 0;
		pTLS->AddressOfIndex		= 0;
		pTLS->EndAddressOfRawData	= 0;
		pTLS->SizeOfZeroFill		= 0;
		pTLS->StartAddressOfRawData = 0;

		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress	= 0;
		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size			= 0;
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$0D")) __stdcall MMI_CloakHeader(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & (INJ_ERASE_HEADER | INJ_FAKE_HEADER)))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	void * base			= pData->pImageBase;
	SIZE_T header_size	= pData->pOptionalHeader->SizeOfHeaders;
	ULONG old_access	= NULL;

	//PE header is R/E only
	if (pData->Flags & INJ_MM_SET_PAGE_PROTECTIONS)
	{
		pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &base, &header_size, PAGE_EXECUTE_READWRITE, &old_access);

		if (NT_FAIL(pData->ntRet))
		{
			return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
		}
	}

	if (pData->Flags & INJ_ERASE_HEADER)
	{
		f->RtlZeroMemory(pData->pImageBase, header_size);
	}
	else if (pData->Flags & INJ_FAKE_HEADER)
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
			return INJ_MM_ERR_CANT_GET_PEB;
		}

		if (!pPEB->Ldr || !pPEB->Ldr->InLoadOrderModuleListHead.Flink || !pPEB->Ldr->InLoadOrderModuleListHead.Flink->Flink)
		{
			return INJ_MM_ERR_INVALID_PEB_DATA;
		}

		auto * ntdll_ldr = ReCa<LDR_DATA_TABLE_ENTRY *>(pPEB->Ldr->InLoadOrderModuleListHead.Flink->Flink);
		if (!ntdll_ldr || !ntdll_ldr->DllBase)
		{
			return INJ_MM_ERR_INVALID_PEB_DATA;
		}

		BYTE * p_ntdll = ReCa<BYTE *>(ntdll_ldr->DllBase);
		IMAGE_DOS_HEADER * p_nt_dos = ReCa<IMAGE_DOS_HEADER *>(p_ntdll);
		IMAGE_NT_HEADERS * p_nt_nt	= ReCa<IMAGE_NT_HEADERS *>(p_ntdll + p_nt_dos->e_lfanew);

		f->RtlZeroMemory(pData->pImageBase, header_size);

		f->memmove(pData->pImageBase, ntdll_ldr->DllBase, min(p_nt_nt->OptionalHeader.SizeOfHeaders, header_size));
	}

	//update PE header protection back to R/E
	if (pData->Flags & INJ_MM_SET_PAGE_PROTECTIONS)
	{
		pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &base, &header_size, old_access, &old_access);

		if (NT_FAIL(pData->ntRet))
		{
			return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
		}
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$0E")) __stdcall MMI_CleanUp(MANUAL_MAPPING_DATA * pData)
{
	auto f = pData->FunctionTable;

	if (pData->pFakeSEHDirectory)
	{
		SIZE_T Size = 0;
		f->NtFreeVirtualMemory(NtCurrentProcess(), ReCa<void **>(&pData->pFakeSEHDirectory), &Size, MEM_RELEASE);
	}

	if (pData->hVEH)
	{
		f->RtlRemoveVectoredExceptionHandler(pData->hVEH);
	}

	if (pData->pDelayImportsHead)
	{
		UnloadAndDeleteDependencyRecord(f, pData->pDelayImportsHead);
	}

	if (pData->pImportsHead)
	{
		UnloadAndDeleteDependencyRecord(f, pData->pImportsHead);
	}

	if (pData->pAllocationBase)
	{
		SIZE_T Size = 0;
		f->NtFreeVirtualMemory(NtCurrentProcess(), ReCa<void **>(&pData->pAllocationBase), &Size, MEM_RELEASE);
	}

	if (pData->pRawData && !(pData->Flags & INJ_MM_MAP_FROM_MEMORY))
	{
		SIZE_T Size = 0;
		f->NtFreeVirtualMemory(NtCurrentProcess(), ReCa<void **>(&pData->pRawData), &Size, MEM_RELEASE);
	}

	if (pData->hDllFile)
	{
		f->NtClose(pData->hDllFile);
	}

	return 0;
}

DWORD __declspec(code_seg(".mmap_sec$14")) MMAP_SEC_END()
{
	return 1337;
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
	NT_FUNC_CONSTRUCTOR_INIT(RtlUnicodeStringToAnsiString);
	NT_FUNC_CONSTRUCTOR_INIT(RtlCompareUnicodeString);
	NT_FUNC_CONSTRUCTOR_INIT(RtlCompareString);

	NT_FUNC_CONSTRUCTOR_INIT(LdrGetDllPath);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpPreprocessDllName);
	NT_FUNC_CONSTRUCTOR_INIT(RtlInsertInvertedFunctionTable);
#ifdef _WIN64
	NT_FUNC_CONSTRUCTOR_INIT(RtlAddFunctionTable);
#endif
	NT_FUNC_CONSTRUCTOR_INIT(LdrpHandleTlsData);

	NT_FUNC_CONSTRUCTOR_INIT(LdrLockLoaderLock);
	NT_FUNC_CONSTRUCTOR_INIT(LdrUnlockLoaderLock);

	NT_FUNC_CONSTRUCTOR_INIT(LdrpDereferenceModule);

	NT_FUNC_CONSTRUCTOR_INIT(LdrProtectMrdata);

	NT_FUNC_CONSTRUCTOR_INIT(RtlAddVectoredExceptionHandler);
	NT_FUNC_CONSTRUCTOR_INIT(RtlRemoveVectoredExceptionHandler);

	NT_FUNC_CONSTRUCTOR_INIT(LdrpModuleBaseAddressIndex);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpMappingInfoIndex);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpHeap);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpInvertedFunctionTable);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpDefaultPath);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpTlsList);
}