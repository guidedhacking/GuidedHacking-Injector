#include "pch.h"

#ifdef _WIN64

#include "Injection Internal.h"
#include "Manual Mapping.h"
#include "WOW64 Shells.h"

using namespace WOW64;

DWORD InjectDLL_WOW64(const wchar_t * szDllFile, HANDLE hTargetProc, INJECTION_MODE Mode, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD Timeout, ERROR_DATA & error_data)
{
	LOG("Begin InjectDLL_WOW64\n");

	if (Mode == INJECTION_MODE::IM_ManualMap)
	{
		LOG("Forwarding call to ManualMap_WOW64\n");

		return MMAP_WOW64::ManualMap_WOW64(szDllFile, hTargetProc, Method, Flags, hOut, Timeout, error_data);
	}

	INJECTION_DATA_INTERNAL_WOW64 data{ 0 };
	data.Flags	= Flags;
	data.Mode	= Mode;

	size_t len = 0;
	HRESULT hr = StringCbLengthW(szDllFile, sizeof(data.Path), &len);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		LOG("StringCbLengthW failed: %08X\n", hr);

		return INJ_ERR_STRINGC_XXX_FAIL;
	}

	if (!data.f.LoadLibraryExW || !data.f.GetLastError)
	{
		HINSTANCE hK32 = GetModuleHandleEx_WOW64(hTargetProc, TEXT("kernel32.dll"));
		GetProcAddressEx_WOW64(hTargetProc, hK32, "LoadLibraryExW", WOW64::LoadLibraryExW_WOW64);
		GetProcAddressEx_WOW64(hTargetProc, hK32, "GetLastError",	WOW64::GetLastError_WOW64);
		data.f.LoadLibraryExW	= WOW64::LoadLibraryExW_WOW64;
		data.f.GetLastError		= WOW64::GetLastError_WOW64;

		if (!data.f.LoadLibraryExW || !data.f.GetLastError)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG("Missing WOW64 specific imports\n");

			return INJ_ERR_GET_PROC_ADDRESS_FAIL;
		}
	}

	data.ModuleFileName.Length		= (WORD)len;
	data.ModuleFileName.MaxLength	= (WORD)sizeof(data.Path);

	hr = StringCbCopyW(data.Path, sizeof(data.Path), szDllFile);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		LOG("StringCbCopyW failed: %08X\n", hr);

		return INJ_ERR_STRINGC_XXX_FAIL;
	}

	LOG("Shell data initialized\n");

	ULONG_PTR ShellSize		= sizeof(InjectionShell_WOW64);
	SIZE_T AllocationSize	= sizeof(INJECTION_DATA_INTERNAL_WOW64) + ShellSize + 0x10;

	BYTE * pAllocBase = ReCa<BYTE*>(VirtualAllocEx(hTargetProc, nullptr, AllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	BYTE * pArg		= pAllocBase;
	BYTE * pShell	= ReCa<BYTE*>(ALIGN_UP(ReCa<ULONG_PTR>(pArg + sizeof(INJECTION_DATA_INTERNAL_WOW64)), 0x10));

	if (!pArg)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG("VirtualAllocEx failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_OUT_OF_MEMORY_EXT;
	}

	LOG("Shellsize = %IX\nTotal size = %08X\npArg = %p\npShell = %p\n", ShellSize, (DWORD)AllocationSize, pArg, pShell);

	if (!WriteProcessMemory(hTargetProc, pArg, &data, sizeof(INJECTION_DATA_INTERNAL_WOW64), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG("WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	if (!WriteProcessMemory(hTargetProc, pShell, InjectionShell_WOW64, ShellSize, nullptr))
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

	if (!ReadProcessMemory(hTargetProc, pArg, &data, sizeof(INJECTION_DATA_INTERNAL_WOW64), nullptr))
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
		INIT_ERROR_DATA(error_data, data.LastError);

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

	LOG("End InjectDLL_WOW64\n");

	return INJ_ERR_SUCCESS;
}

INJECTION_FUNCTION_TABLE_WOW64::INJECTION_FUNCTION_TABLE_WOW64()
{
	WOW64_FUNC_CONSTRUCTOR_INIT(LoadLibraryExW);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrLoadDll);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpLoadDll);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpLoadDllInternal);

	WOW64_FUNC_CONSTRUCTOR_INIT(GetLastError);

	WOW64_FUNC_CONSTRUCTOR_INIT(memmove);
	WOW64_FUNC_CONSTRUCTOR_INIT(RtlZeroMemory);
	WOW64_FUNC_CONSTRUCTOR_INIT(RtlFreeHeap);

	WOW64_FUNC_CONSTRUCTOR_INIT(RtlRbRemoveNode);

	WOW64_FUNC_CONSTRUCTOR_INIT(NtProtectVirtualMemory);

	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpModuleBaseAddressIndex);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpMappingInfoIndex);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpHeap);
}

#endif