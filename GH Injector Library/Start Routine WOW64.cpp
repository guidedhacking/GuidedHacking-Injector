#include "pch.h"

#ifdef _WIN64

#include "Start Routine.h"

DWORD StartRoutine_WOW64(HANDLE hTargetProc, f_Routine_WOW64 pRoutine, DWORD pArg, LAUNCH_METHOD Method, DWORD Flags, DWORD & Out, DWORD Timeout, ERROR_DATA & error_data)
{
	DWORD Ret = 0;
	
	switch (Method)
	{
		case LAUNCH_METHOD::LM_NtCreateThreadEx:
			Ret = SR_NtCreateThreadEx_WOW64(hTargetProc, pRoutine, pArg, Flags, Out, Timeout, error_data);
			break;

		case LAUNCH_METHOD::LM_HijackThread:
			Ret = SR_HijackThread_WOW64(hTargetProc, pRoutine, pArg, Out, Timeout, error_data);
			break;

		case LAUNCH_METHOD::LM_SetWindowsHookEx:
		case LAUNCH_METHOD::LM_KernelCallback:
		{
			NTSTATUS ntRet = 0;
			ULONG OwnSession	= GetSessionId(GetCurrentProcess(), ntRet);
			ULONG TargetSession = GetSessionId(hTargetProc, ntRet);

			if (TargetSession == SESSION_ID_INVALID)
			{
				INIT_ERROR_DATA(error_data, (DWORD)ntRet);

				Ret = SR_ERR_CANT_QUERY_SESSION_ID;
				break;
			}
			else if (OwnSession != SESSION_ID_LOCAL_SYSTEM && OwnSession != TargetSession)
			{
				INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

				Ret = SR_ERR_NOT_LOCAL_SYSTEM;
				break;
			}
			else if (TargetSession == OwnSession)
			{
				TargetSession = SESSION_ID_INVALID;
			}

			if (Method == LAUNCH_METHOD::LM_SetWindowsHookEx)
			{
				Ret = SR_SetWindowsHookEx_WOW64(hTargetProc, pRoutine, pArg, TargetSession, Out, Timeout, error_data);
			}
			else
			{
				Ret = SR_KernelCallback_WOW64(hTargetProc, pRoutine, pArg, TargetSession, Out, Timeout, error_data);
			}
			
			break;
		}
		
		case LAUNCH_METHOD::LM_QueueUserAPC:
			Ret = SR_QueueUserAPC_WOW64(hTargetProc, pRoutine, pArg, Out, Timeout, error_data);
			break;

		case LAUNCH_METHOD::LM_FakeVEH:
			Ret = SR_FakeVEH_WOW64(hTargetProc, pRoutine, pArg, Out, Timeout, error_data);
			break;

		default:
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			Ret = SR_ERR_INVALID_LAUNCH_METHOD;
			break;
	}
	
	return Ret;
}

#endif