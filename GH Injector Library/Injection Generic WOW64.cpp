/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

#include "pch.h"

#ifdef _WIN64

#include "Injection Internal.h"
#include "WOW64 Shells.h"

using namespace WOW64;

DWORD InjectDLL_WOW64(const INJECTION_SOURCE & Source, HANDLE hTargetProc, INJECTION_MODE Mode, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD Timeout, ERROR_DATA & error_data)
{
	LOG(1, "Begin InjectDLL_WOW64\n");

	if (Mode == INJECTION_MODE::IM_ManualMap)
	{
		LOG(1, "Forwarding call to ManualMap_WOW64\n");

		return MMAP_WOW64::ManualMap_WOW64(Source, hTargetProc, Method, Flags, hOut, Timeout, error_data);
	}

	INJECTION_DATA_MAPPED_WOW64 data{ 0 };
	data.Flags			= Flags;
	data.Mode			= Mode;
	data.OSVersion		= GetOSVersion();
	data.OSBuildNumber	= GetOSBuildVersion();

	size_t len = Source.DllPath.length();
	size_t max_len = sizeof(data.Path) / sizeof(wchar_t);
	if (len > max_len)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "Path too long: %d characters, buffer size: %d\n", len, max_len);

		return INJ_ERR_STRING_TOO_LONG;
	}
		
	data.ModuleFileName.Length		= (WORD)(len * sizeof(wchar_t));
	data.ModuleFileName.MaxLength	= (WORD)sizeof(data.Path);
	Source.DllPath.copy(data.Path, Source.DllPath.length());

	LOG(1, "Shell data initialized\n");

	ULONG_PTR ShellSize		= sizeof(InjectionShell_WOW64);
	ULONG_PTR VEHShellSize	= sizeof(VectoredHandlerShell_WOW64);

	if (!(Flags & INJ_UNLINK_FROM_PEB))
	{
		VEHShellSize = 0;
	}

	SIZE_T AllocationSize	= sizeof(INJECTION_DATA_MAPPED_WOW64) + ShellSize + BASE_ALIGNMENT;
	BYTE * pAllocBase = ReCa<BYTE *>(VirtualAllocEx(hTargetProc, nullptr, AllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	
	BYTE * pArg			= pAllocBase;
	BYTE * pShell		= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pArg + sizeof(INJECTION_DATA_MAPPED_WOW64)), BASE_ALIGNMENT));
	BYTE * pVEHShell	= nullptr;

	if (!pArg)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "VirtualAllocEx failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_OUT_OF_MEMORY_EXT;
	}

	if (VEHShellSize)
	{
		pVEHShell = ReCa<BYTE *>(VirtualAllocEx(hTargetProc, nullptr, VEHShellSize + sizeof(VEH_SHELL_DATA) + BASE_ALIGNMENT, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		//VEH_SHELL_DATA is bigger than the wow64 version of it, no need to define it, will be filled using wow64 anyway

		if (!pVEHShell)
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(1, "VirtualAllocEx failed: %08X\n", error_data.AdvErrorCode);

			VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

			return INJ_ERR_OUT_OF_MEMORY_EXT;
		}

		data.pVEHShell		= MDWD(pVEHShell);
		data.VEHShellSize	= MDWD(VEHShellSize);
	}

	LOG(2, "Shellsize	= %08X\n", MDWD(ShellSize));
	LOG(2, "Total size	= %08X\n", MDWD(AllocationSize));
	LOG(2, "pArg        = %08X\n", MDWD(pArg));
	LOG(2, "pShell      = %08X\n", MDWD(pShell));

	if (VEHShellSize)
	{
		LOG(2, "pVEHShell   = %08X\n", MDWD(pVEHShell));
	}

	if (!WriteProcessMemory(hTargetProc, pArg, &data, sizeof(INJECTION_DATA_MAPPED_WOW64), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		if (pVEHShell)
		{
			VirtualFreeEx(hTargetProc, pVEHShell, 0, MEM_RELEASE);
		}

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	if (!WriteProcessMemory(hTargetProc, pShell, InjectionShell_WOW64, ShellSize, nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		if (pVEHShell)
		{
			VirtualFreeEx(hTargetProc, pVEHShell, 0, MEM_RELEASE);
		}

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

			if (pVEHShell)
			{
				VirtualFreeEx(hTargetProc, pVEHShell, 0, MEM_RELEASE);
			}

			VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

			return INJ_ERR_WPM_FAIL;
		}

		LOG(1, "VEHShell written to memory\n");
	}

	LOG(1, "Entering StartRoutine_WOW64\n");

	if (Flags & INJ_THREAD_CREATE_CLOAKED)
	{
		Flags |= (INJ_CTF_FAKE_START_ADDRESS | INJ_CTF_HIDE_FROM_DEBUGGER);
	}

	DWORD remote_ret = 0;
	DWORD dwRet = StartRoutine_WOW64(hTargetProc, (f_Routine_WOW64)(MDWD(pShell)), MDWD(pArg), Method, Flags, remote_ret, Timeout, error_data);

	LOG(1, "Return from StartRoutine_WOW64\n");

	if (dwRet != SR_ERR_SUCCESS)
	{
		LOG(1, "StartRoutine_WOW64 failed: %08X\n", dwRet);

		if (Method != LAUNCH_METHOD::LM_QueueUserAPC && !(Method == LAUNCH_METHOD::LM_HijackThread && dwRet == SR_HT_ERR_REMOTE_TIMEOUT))
		{
			if (pVEHShell)
			{
				VirtualFreeEx(hTargetProc, pVEHShell, 0, MEM_RELEASE);
			}

			VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);
		}

		return dwRet;
	}

	LOG(1, "Fetching routine data\n");

	if (!ReadProcessMemory(hTargetProc, pArg, &data, sizeof(INJECTION_DATA_MAPPED_WOW64), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "ReadProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		if (Method != LAUNCH_METHOD::LM_QueueUserAPC)
		{
			if (pVEHShell)
			{
				VirtualFreeEx(hTargetProc, pVEHShell, 0, MEM_RELEASE);
			}

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

INJECTION_FUNCTION_TABLE_WOW64::INJECTION_FUNCTION_TABLE_WOW64()
{
	WOW64_FUNC_CONSTRUCTOR_INIT(LoadLibraryExW);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrLoadDll);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpLoadDll);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpLoadDllInternal);

	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpPreprocessDllName);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpDereferenceModule);

	WOW64_FUNC_CONSTRUCTOR_INIT(GetLastError);

	WOW64_FUNC_CONSTRUCTOR_INIT(memmove);
	WOW64_FUNC_CONSTRUCTOR_INIT(RtlZeroMemory);

	WOW64_FUNC_CONSTRUCTOR_INIT(RtlRbRemoveNode);

	WOW64_FUNC_CONSTRUCTOR_INIT(NtProtectVirtualMemory);

	WOW64_FUNC_CONSTRUCTOR_INIT(RtlAddVectoredExceptionHandler);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrProtectMrdata);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpInvertedFunctionTable);

	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpModuleBaseAddressIndex);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpMappingInfoIndex);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpDefaultPath);
}

#endif