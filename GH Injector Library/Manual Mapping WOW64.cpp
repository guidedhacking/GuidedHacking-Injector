#include "pch.h"

#ifdef _WIN64

#include "Manual Mapping.h"

using namespace WOW64;
using namespace MMAP_WOW64;

BYTE ManualMapping_Shell_WOW64[] =
{
	0
};

DWORD MMAP_WOW64::ManualMap_WOW64(const wchar_t * szDllFile, HANDLE hTargetProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, ERROR_DATA & error_data)
{
	MANUAL_MAPPING_DATA_WOW64			data;
	data.Flags = Flags;

	data.DllPath.MaxLength = sizeof(data.szPathBuffer);
	data.DllPath.Length		= (WORD)(lstrlenW(szDllFile) * sizeof(wchar_t));
	memcpy(data.szPathBuffer, szDllFile, data.DllPath.Length);

	const wchar_t * pDllName = wcsrchr(szDllFile, '\\') + 1;
	data.DllName.MaxLength	= sizeof(data.szNameBuffer);
	data.DllName.Length		= (WORD)(lstrlenW(pDllName) * sizeof(wchar_t));
	memcpy(data.szNameBuffer, pDllName, data.DllName.Length);

	ULONG_PTR ShellSize = sizeof(ManualMapping_Shell_WOW64);
	auto AllocationSize = sizeof(MANUAL_MAPPING_DATA_WOW64) + ShellSize + 0x10;
	BYTE * pAllocBase		= ReCa<BYTE *>(VirtualAllocEx(hTargetProc, nullptr, AllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

	BYTE * pArg		= pAllocBase;
	BYTE * pShell	= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pArg) + sizeof(MANUAL_MAPPING_DATA_WOW64), 0x10));

	if (!pArg)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		return INJ_ERR_OUT_OF_MEMORY_EXT;
	}

	if (!WriteProcessMemory(hTargetProc, pArg, &data, sizeof(MANUAL_MAPPING_DATA_WOW64), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	if (!WriteProcessMemory(hTargetProc, pShell, ManualMapping_Shell_WOW64, ShellSize, nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	DWORD remote_ret = 0;
	DWORD dwRet = StartRoutine_WOW64(hTargetProc, (f_Routine_WOW64)(MDWD(pShell)), MDWD(pArg), Method, (Flags & INJ_THREAD_CREATE_CLOAKED) != 0, remote_ret, error_data);

	if (dwRet != SR_ERR_SUCCESS)
	{
		if (Method != LAUNCH_METHOD::LM_QueueUserAPC && !(Method == LAUNCH_METHOD::LM_HijackThread && dwRet == SR_HT_ERR_REMOTE_TIMEOUT))
		{
			VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);
		}

		return dwRet;
	}

	if (!ReadProcessMemory(hTargetProc, pAllocBase, &data, sizeof(MANUAL_MAPPING_DATA_WOW64), nullptr))
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

	hOut = ReCa<HINSTANCE>(MPTR(data.hRet));

	return 0;
}

MANUAL_MAPPING_FUNCTION_TABLE_WOW64::MANUAL_MAPPING_FUNCTION_TABLE_WOW64()
{
	WOW64_FUNC_CONSTRUCTOR_INIT(NtOpenFile);
	WOW64_FUNC_CONSTRUCTOR_INIT(NtReadFile);
	WOW64_FUNC_CONSTRUCTOR_INIT(NtSetInformationFile);
	WOW64_FUNC_CONSTRUCTOR_INIT(NtQueryInformationFile);

	WOW64_FUNC_CONSTRUCTOR_INIT(NtCreateSection);
	WOW64_FUNC_CONSTRUCTOR_INIT(NtMapViewOfSection);
	WOW64_FUNC_CONSTRUCTOR_INIT(NtUnmapViewOfSection);

	WOW64_FUNC_CONSTRUCTOR_INIT(NtAllocateVirtualMemory);
	WOW64_FUNC_CONSTRUCTOR_INIT(NtProtectVirtualMemory);
	WOW64_FUNC_CONSTRUCTOR_INIT(NtFreeVirtualMemory);

	WOW64_FUNC_CONSTRUCTOR_INIT(RtlMoveMemory);
	WOW64_FUNC_CONSTRUCTOR_INIT(RtlAllocateHeap);
	WOW64_FUNC_CONSTRUCTOR_INIT(RtlFreeHeap);

	WOW64_FUNC_CONSTRUCTOR_INIT(LdrGetDllHandleEx);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpLoadDll);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrUnloadDll);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrGetProcedureAddress);

	WOW64_FUNC_CONSTRUCTOR_INIT(LdrLockLoaderLock);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrUnlockLoaderLock);

	WOW64_FUNC_CONSTRUCTOR_INIT(RtlAnsiStringToUnicodeString);
	WOW64_FUNC_CONSTRUCTOR_INIT(RtlUnicodeStringToAnsiString);
	WOW64_FUNC_CONSTRUCTOR_INIT(RtlInitUnicodeString);
	WOW64_FUNC_CONSTRUCTOR_INIT(RtlHashUnicodeString);

	WOW64_FUNC_CONSTRUCTOR_INIT(RtlRbInsertNodeEx);
	WOW64_FUNC_CONSTRUCTOR_INIT(RtlRbRemoveNode);

	WOW64_FUNC_CONSTRUCTOR_INIT(RtlGetSystemTimePrecise);

	WOW64_FUNC_CONSTRUCTOR_INIT(NtClose);

	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpPreprocessDllName);
	WOW64_FUNC_CONSTRUCTOR_INIT(RtlInsertInvertedFunctionTable);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpHandleTlsData);

	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpModuleBaseAddressIndex);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpMappingInfoIndex);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpHashTable);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpHeap);
}

#endif