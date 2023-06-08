#include "pch.h"

#ifdef _WIN64

#include "Manual Mapping.h"
#include "WOW64 Shells.h"

using namespace WOW64;
using namespace MMAP_WOW64;

DWORD MMAP_WOW64::ManualMap_WOW64(const INJECTION_SOURCE & Source, HANDLE hTargetProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD Timeout, ERROR_DATA & error_data)
{
	LOG(1, "Begin ManualMap_WOW64\n");

	MANUAL_MAPPING_DATA_WOW64 data{ 0 };
	data.Flags			= Flags;
	data.OSVersion		= GetOSVersion();
	data.OSBuildNumber	= GetOSBuildVersion();

	if (Source.FromMemory)
	{
		data.RawSize = Source.RawSize;
	}
	else
	{
		size_t len = Source.DllPath.length();
		size_t max_len = sizeof(data.szPathBuffer) / sizeof(wchar_t);
		if (len > max_len)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(1, "Path too long: %d characters, buffer size: %d\n", len, max_len);

			return INJ_ERR_STRING_TOO_LONG;
		}

		data.DllPath.Length = (WORD)(len * sizeof(wchar_t));
		data.DllPath.MaxLength = (WORD)sizeof(data.szPathBuffer);
		Source.DllPath.copy(data.szPathBuffer, Source.DllPath.length());
	}

	LOG(1, "Shell data initialized\n");

	if (Flags & INJ_MM_SHIFT_MODULE_BASE && !(Flags & INJ_MM_SET_PAGE_PROTECTIONS))
	{
		DWORD seed = GetTickCount();
		std::mt19937 gen(seed);
		std::uniform_int_distribution<WORD> dis(MIN_SHIFT_OFFSET, MAX_SHIFT_OFFSET);

		WORD shift_offset = dis(gen);
		shift_offset = ALIGN_UP(shift_offset, BASE_ALIGNMENT);

		data.ShiftOffset = shift_offset;

		LOG(1, "Shift offset = %04X\n", shift_offset);
	}

	ULONG_PTR ShellSize		= WOW64_SEC_END - ManualMapping_Shell_WOW64;
	ULONG_PTR VEHShellSize	= sizeof(VectoredHandlerShell_WOW64);

	if ((Flags & INJ_MM_ENABLE_EXCEPTIONS) == 0)
	{
		VEHShellSize = 0;
	}

	auto AllocationSize = sizeof(MANUAL_MAPPING_DATA_WOW64) + sizeof(MANUAL_MAPPING_FUNCTION_TABLE_WOW64) + ShellSize + VEHShellSize + BASE_ALIGNMENT * 4;
	if (Source.FromMemory)
	{
		AllocationSize += (SIZE_T)Source.RawSize + BASE_ALIGNMENT;
	}

	BYTE * pAllocBase = ReCa<BYTE *>(VirtualAllocEx(hTargetProc, nullptr, AllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pAllocBase)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "VirtualAllocEx failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_OUT_OF_MEMORY_EXT;
	}

	BYTE * pArg				= pAllocBase;
	BYTE * pShells			= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pArg)			+ sizeof(MANUAL_MAPPING_DATA_WOW64),			BASE_ALIGNMENT));
	BYTE * pVEHShell		= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pShells)		+ ShellSize,									BASE_ALIGNMENT));
	BYTE * pFunctionTable	= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pVEHShell)		+ VEHShellSize,									BASE_ALIGNMENT));
	BYTE * pRawData			= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pFunctionTable) + sizeof(MANUAL_MAPPING_FUNCTION_TABLE_WOW64),	BASE_ALIGNMENT));

	auto table_local = new(std::nothrow) MANUAL_MAPPING_FUNCTION_TABLE_WOW64();
	if (!table_local)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "operator new failed: %08X\n", error_data.AdvErrorCode);

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_OUT_OF_MEMORY_NEW;
	}

	BYTE * mmap_sec_wow64_base = ManualMapping_Shell_WOW64;

	table_local->MMP_Shell = MDWD(pShells);
	table_local->MMIP_MapSections			= MDWD(pShells + MMI_MapSections_WOW64			- mmap_sec_wow64_base);
	table_local->MMIP_RelocateImage			= MDWD(pShells + MMI_RelocateImage_WOW64		- mmap_sec_wow64_base);
	table_local->MMIP_InitializeCookie		= MDWD(pShells + MMI_InitializeCookie_WOW64		- mmap_sec_wow64_base);
	table_local->MMIP_LoadImports			= MDWD(pShells + MMI_LoadImports_WOW64			- mmap_sec_wow64_base);
	table_local->MMIP_LoadDelayImports		= MDWD(pShells + MMI_LoadDelayImports_WOW64		- mmap_sec_wow64_base);
	table_local->MMIP_SetPageProtections	= MDWD(pShells + MMI_SetPageProtections_WOW64	- mmap_sec_wow64_base);
	table_local->MMIP_EnableExceptions		= MDWD(pShells + MMI_EnableExceptions_WOW64		- mmap_sec_wow64_base);
	table_local->MMIP_HandleTLS				= MDWD(pShells + MMI_HandleTLS_WOW64			- mmap_sec_wow64_base);
	table_local->MMIP_ExecuteDllMain		= MDWD(pShells + MMI_ExecuteDllMain_WOW64		- mmap_sec_wow64_base);
	table_local->MMIP_CleanDataDirectories	= MDWD(pShells + MMI_CleanDataDirectories_WOW64	- mmap_sec_wow64_base);
	table_local->MMIP_CloakHeader			= MDWD(pShells + MMI_CloakHeader_WOW64			- mmap_sec_wow64_base);
	table_local->MMIP_CleanUp				= MDWD(pShells + MMI_CleanUp_WOW64				- mmap_sec_wow64_base);

	table_local->MMIHP_ResolveFilePath		= MDWD(pShells + MMIH_ResolveFilePath_WOW64			- mmap_sec_wow64_base);
	table_local->MMIHP_PreprocessModuleName	= MDWD(pShells + MMIH_PreprocessModuleName_WOW64	- mmap_sec_wow64_base);
	table_local->MMIHP_LoadModule			= MDWD(pShells + MMIH_LoadModule_WOW64				- mmap_sec_wow64_base);

	data.FunctionTable = MDWD(pFunctionTable);

	if (VEHShellSize)
	{
		data.pVEHShell		= MDWD(pVEHShell);
		data.VEHShellSize	= MDWD(VEHShellSize);
	}

	if (Source.FromMemory)
	{
		data.pRawData = MDWD(pRawData);
	}

	LOG(2, "Shellsize      = %08X\n", MDWD(ShellSize));
	LOG(2, "Total size     = %08X\n", MDWD(AllocationSize));
	LOG(2, "pArg           = %08X\n", MDWD(pArg));
	LOG(2, "pShells        = %08X\n", MDWD(pShells));

	if (VEHShellSize)
	{
		LOG(2, "pVEHShell   = %08X\n", MDWD(pVEHShell));
	}

	if (!WriteProcessMemory(hTargetProc, pArg, &data, sizeof(MANUAL_MAPPING_DATA_WOW64), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		delete table_local;
		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	LOG(1, "Shelldata written to memory\n");

	if (!WriteProcessMemory(hTargetProc, pShells, mmap_sec_wow64_base, ShellSize, nullptr))
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
		if (!WriteProcessMemory(hTargetProc, pVEHShell, VectoredHandlerShell_WOW64, VEHShellSize, nullptr))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(1, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

			delete table_local;
			VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

			return INJ_ERR_WPM_FAIL;
		}

		LOG(1, "VEHShell written to memory\n");
	}

	if (!WriteProcessMemory(hTargetProc, pFunctionTable, table_local, sizeof(MANUAL_MAPPING_FUNCTION_TABLE_WOW64), nullptr))
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

	LOG(1, "Entering StartRoutine_WOW64\n");

	DWORD remote_ret = 0;
	DWORD dwRet = StartRoutine_WOW64(hTargetProc, (f_Routine_WOW64)(MDWD(pShells)), MDWD(pArg), Method, Flags, remote_ret, Timeout, error_data);

	LOG(1, "Return from StartRoutine_WOW64\n");

	if (dwRet != SR_ERR_SUCCESS)
	{
		LOG(1, "StartRoutine_WOW64 failed: %08X\n", dwRet);

		if (Method != LAUNCH_METHOD::LM_QueueUserAPC && !(Method == LAUNCH_METHOD::LM_HijackThread && dwRet == SR_HT_ERR_REMOTE_TIMEOUT))
		{
			VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);
		}

		return dwRet;
	}

	LOG(1, "Fetching routine data\n");

	if (!ReadProcessMemory(hTargetProc, pAllocBase, &data, sizeof(MANUAL_MAPPING_DATA_WOW64), nullptr))
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

	hOut = ReCa<HINSTANCE>(MPTR(data.hRet));

	LOG(1, "Imagebase = %p\n", ReCa<void *>(hOut));

	return INJ_ERR_SUCCESS;
}

MANUAL_MAPPING_FUNCTION_TABLE_WOW64::MANUAL_MAPPING_FUNCTION_TABLE_WOW64()
{
	WOW64_FUNC_CONSTRUCTOR_INIT(NtOpenFile);
	WOW64_FUNC_CONSTRUCTOR_INIT(NtReadFile);
	WOW64_FUNC_CONSTRUCTOR_INIT(NtClose);

	WOW64_FUNC_CONSTRUCTOR_INIT(NtSetInformationFile);
	WOW64_FUNC_CONSTRUCTOR_INIT(NtQueryInformationFile);

	WOW64_FUNC_CONSTRUCTOR_INIT(NtAllocateVirtualMemory);
	WOW64_FUNC_CONSTRUCTOR_INIT(NtProtectVirtualMemory);
	WOW64_FUNC_CONSTRUCTOR_INIT(NtFreeVirtualMemory);

	WOW64_FUNC_CONSTRUCTOR_INIT(NtCreateSection);
	WOW64_FUNC_CONSTRUCTOR_INIT(NtMapViewOfSection);

	WOW64_FUNC_CONSTRUCTOR_INIT(memmove);
	WOW64_FUNC_CONSTRUCTOR_INIT(RtlZeroMemory);
	WOW64_FUNC_CONSTRUCTOR_INIT(RtlAllocateHeap);
	WOW64_FUNC_CONSTRUCTOR_INIT(RtlFreeHeap);

	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpLoadDll);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpLoadDllInternal);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrGetProcedureAddress);

	WOW64_FUNC_CONSTRUCTOR_INIT(LdrUnloadDll);

	WOW64_FUNC_CONSTRUCTOR_INIT(RtlAnsiStringToUnicodeString);
	WOW64_FUNC_CONSTRUCTOR_INIT(RtlUnicodeStringToAnsiString);
	WOW64_FUNC_CONSTRUCTOR_INIT(RtlCompareUnicodeString);
	WOW64_FUNC_CONSTRUCTOR_INIT(RtlCompareString);

	WOW64_FUNC_CONSTRUCTOR_INIT(LdrGetDllPath);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpPreprocessDllName);
	WOW64_FUNC_CONSTRUCTOR_INIT(RtlInsertInvertedFunctionTable);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpHandleTlsData);

	WOW64_FUNC_CONSTRUCTOR_INIT(LdrLockLoaderLock);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrUnlockLoaderLock);

	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpDereferenceModule);

	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpMappingInfoIndex);

	WOW64_FUNC_CONSTRUCTOR_INIT(LdrProtectMrdata);

	WOW64_FUNC_CONSTRUCTOR_INIT(RtlAddVectoredExceptionHandler);
	WOW64_FUNC_CONSTRUCTOR_INIT(RtlRemoveVectoredExceptionHandler);

	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpModuleBaseAddressIndex);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpMappingInfoIndex);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpHeap);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpInvertedFunctionTable);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpDefaultPath);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpTlsList);
}

#endif