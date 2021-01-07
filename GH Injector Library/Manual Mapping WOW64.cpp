#include "pch.h"

#ifdef _WIN64

#include "Manual Mapping.h"
#include "WOW64 Shells.h"

using namespace WOW64;
using namespace MMAP_WOW64;

DWORD MMAP_WOW64::ManualMap_WOW64(const wchar_t * szDllFile, HANDLE hTargetProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD Timeout, ERROR_DATA & error_data)
{
	LOG("Begin ManualMap_WOW64\n");

	MANUAL_MAPPING_DATA_WOW64 data{ 0 };
	data.Flags = Flags;

	size_t len = 0;
	HRESULT hr = StringCbLengthW(szDllFile, sizeof(data.szPathBuffer), &len);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		LOG("StringCbLengthW failed: %08X\n", hr);

		return INJ_ERR_STRINGC_XXX_FAIL;
	}
	
	data.DllPath.Length		= (WORD)len;
	data.DllPath.MaxLength	= (WORD)sizeof(data.szPathBuffer);

	hr = StringCbCopyW(data.szPathBuffer, sizeof(data.szPathBuffer), szDllFile);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		LOG("StringCbCopyW failed: %08X\n", hr);

		return INJ_ERR_STRINGC_XXX_FAIL;
	}

	const wchar_t * pDllName = wcsrchr(szDllFile, '\\');
	if (!pDllName)
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		LOG("wcsrchr failed\n");

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

		LOG("StringCbLengthW failed: %08X\n", hr);

		return INJ_ERR_STRINGC_XXX_FAIL;
	}
	
	data.DllName.Length		= (WORD)len;
	data.DllName.MaxLength	= (WORD)sizeof(data.szNameBuffer);

	hr = StringCbCopyW(data.szNameBuffer, sizeof(data.szNameBuffer), pDllName);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		LOG("StringCbCopyW failed: %08X\n", hr);

		return INJ_ERR_STRINGC_XXX_FAIL;
	}

	LOG("Shell data initialized\n");

	ULONG_PTR ShellSize = sizeof(ManualMapping_Shell_WOW64);
	auto AllocationSize = sizeof(MANUAL_MAPPING_DATA_WOW64) + ShellSize + 0x10;
	BYTE * pAllocBase	= ReCa<BYTE*>(VirtualAllocEx(hTargetProc, nullptr, AllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

	BYTE * pArg		= pAllocBase;
	BYTE * pShell	= ReCa<BYTE*>(ALIGN_UP(ReCa<ULONG_PTR>(pArg) + sizeof(MANUAL_MAPPING_DATA_WOW64), 0x10));

	if (!pArg)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG("VirtualAllocEx failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_OUT_OF_MEMORY_EXT;
	}

	LOG("Shellsize = %IX\nTotal size = %08X\npArg = %p\npShell = %p\n", ShellSize, (DWORD)AllocationSize, pArg, pShell);

	if (!WriteProcessMemory(hTargetProc, pArg, &data, sizeof(MANUAL_MAPPING_DATA_WOW64), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG("WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	if (!WriteProcessMemory(hTargetProc, pShell, ManualMapping_Shell_WOW64, ShellSize, nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG("WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	LOG("Shell written to memory\n");

	LOG("Entering StartRoutine_WOW64\n");

	DWORD remote_ret = 0;
	DWORD dwRet = StartRoutine_WOW64(hTargetProc, (f_Routine_WOW64)(MDWD(pShell)), MDWD(pArg), Method, (Flags & INJ_THREAD_CREATE_CLOAKED) != 0, remote_ret, Timeout, error_data);

	LOG("Return from StartRoutine_WOW64\n");

	if (dwRet != SR_ERR_SUCCESS)
	{
		LOG("StartRoutine_WOW64 failed: %08X\n", dwRet);

		if (Method != LAUNCH_METHOD::LM_QueueUserAPC && !(Method == LAUNCH_METHOD::LM_HijackThread && dwRet == SR_HT_ERR_REMOTE_TIMEOUT))
		{
			VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);
		}

		return dwRet;
	}

	LOG("Fetching routine data\n");

	if (!ReadProcessMemory(hTargetProc, pAllocBase, &data, sizeof(MANUAL_MAPPING_DATA_WOW64), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG("ReadProcessMemory failed: %08X\n", error_data.AdvErrorCode);

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

		LOG("Shell failed: %08X\n", remote_ret);

		return remote_ret;
	}

	if (!data.hRet)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG("Shell failed\n");

		return INJ_ERR_FAILED_TO_LOAD_DLL;
	}

	LOG("Shell returned successfully\n");

	hOut = ReCa<HINSTANCE>(MPTR(data.hRet));

	LOG("Imagebase = %p\n", ReCa<void *>(hOut));

	LOG("End ManualMap_WOW64\n");

	return 0;
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

	WOW64_FUNC_CONSTRUCTOR_INIT(memmove);
	WOW64_FUNC_CONSTRUCTOR_INIT(RtlZeroMemory);
	WOW64_FUNC_CONSTRUCTOR_INIT(RtlAllocateHeap);
	WOW64_FUNC_CONSTRUCTOR_INIT(RtlFreeHeap);

	WOW64_FUNC_CONSTRUCTOR_INIT(LdrGetDllHandleEx);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpLoadDllInternal);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrGetProcedureAddress);

	WOW64_FUNC_CONSTRUCTOR_INIT(RtlAnsiStringToUnicodeString);

	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpPreprocessDllName);
	WOW64_FUNC_CONSTRUCTOR_INIT(RtlInsertInvertedFunctionTable);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpHandleTlsData);

	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpAcquireLoaderLock);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpReleaseLoaderLock);

	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpModuleBaseAddressIndex);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpMappingInfoIndex);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpHeap);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpInvertedFunctionTable);
}

#endif