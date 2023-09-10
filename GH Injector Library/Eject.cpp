/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

#include "pch.h"

#include "Eject.h"
#include "Start Routine.h"

bool EjectDll(HANDLE hTargetProc, HINSTANCE hModule, bool WOW64)
{
	LOG(3, "EjectDll called\n");
	LOG(4, "PID     = %08X\n", GetProcessId(hTargetProc));
	LOG(4, "hModule = %p\n", hModule);

	ERROR_DATA eject_data;
	DWORD remote_ret	= 0;
	DWORD ret			= 0;

#ifdef _WIN64
	if (WOW64)
	{
		ret = StartRoutine_WOW64(hTargetProc, WOW64::LdrUnloadDll_WOW64, MDWD(hModule), LAUNCH_METHOD::LM_NtCreateThreadEx, NULL, remote_ret, INJ_EJECT_TIMEOUT, eject_data);
	}
	else
	{
		ret = StartRoutine(hTargetProc, ReCa<f_Routine>(NATIVE::LdrUnloadDll), hModule, LAUNCH_METHOD::LM_NtCreateThreadEx, NULL, remote_ret, INJ_EJECT_TIMEOUT, eject_data);
	}
#else
	UNREFERENCED_PARAMETER(WOW64);

	ret = StartRoutine(hTargetProc, ReCa<f_Routine>(NATIVE::LdrUnloadDll), hModule, LAUNCH_METHOD::LM_NtCreateThreadEx, NULL, remote_ret, INJ_EJECT_TIMEOUT, eject_data);
#endif

	if (ret != SR_ERR_SUCCESS)
	{
		LOG(3, "Failed to eject dll:\n");
		LOG(4, "ret        = %08X\n", ret);
		LOG(4, "advanced   = %08X\n", eject_data.AdvErrorCode);

		return false;
	}
	else if (NT_FAIL(remote_ret))
	{
		LOG(3, "Failed to eject dll:\n");
		LOG(4, "remote_ret = %08X:\n", remote_ret);

		return false;
	}

	LOG(3, "Dll ejected successfully\n");

	return true;
}

bool EjectHijackLibrary(HANDLE hTargetProc, HINSTANCE hInjectionModuleEx, bool Interrupt)
{
	LOG(2, "Ejecting hijack library\n");

	if (!Interrupt)
	{
		return EjectDll(hTargetProc, hInjectionModuleEx);
	}

	ERROR_DATA interrupt_data;
	DWORD remote_ret				= 0;
	DWORD ret						= 0;
	f_Routine pInterruptDownloadEx	= ReCa<f_Routine>(ReCa<UINT_PTR>(InterruptDownloadEx) - ReCa<UINT_PTR>(g_hInjMod) + ReCa<UINT_PTR>(hInjectionModuleEx));

	ret = StartRoutine(hTargetProc, pInterruptDownloadEx, nullptr, LAUNCH_METHOD::LM_NtCreateThreadEx, NULL, remote_ret, INJ_EJECT_TIMEOUT, interrupt_data);

	if (ret != SR_ERR_SUCCESS)
	{
		LOG(2, "Failed to interrupt hijack library:\n");
		LOG(3, "ret        = %08X\n", ret);
		LOG(3, "advanced   = %08X\n", interrupt_data.AdvErrorCode);
	} //try to eject even if interrupt failed
	
	return EjectDll(hTargetProc, hInjectionModuleEx);
}