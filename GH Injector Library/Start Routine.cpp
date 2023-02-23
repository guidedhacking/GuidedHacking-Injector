#include "pch.h"

#include "Start Routine.h"

DWORD StartRoutine(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, LAUNCH_METHOD Method, DWORD Flags, DWORD & Out, DWORD Timeout, ERROR_DATA & error_data)
{
	DWORD Ret = 0;
	
	switch (Method)
	{
		case LAUNCH_METHOD::LM_NtCreateThreadEx:
			Ret = SR_NtCreateThreadEx(hTargetProc, pRoutine, pArg, Flags, Out, Timeout, error_data);
			break;

		case LAUNCH_METHOD::LM_HijackThread:
			Ret = SR_HijackThread(hTargetProc, pRoutine, pArg, Out, Timeout, error_data);
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
			else if (OwnSession == TargetSession)
			{
				TargetSession = SESSION_ID_INVALID;
			}

			if (Method == LAUNCH_METHOD::LM_SetWindowsHookEx)
			{
				Ret = SR_SetWindowsHookEx(hTargetProc, pRoutine, pArg, TargetSession, Out, Timeout, error_data);
			}
			else
			{
				Ret = SR_KernelCallback(hTargetProc, pRoutine, pArg, TargetSession, Out, Timeout, error_data);
			}

			break;
		}

		case LAUNCH_METHOD::LM_QueueUserAPC:
			Ret = SR_QueueUserAPC(hTargetProc, pRoutine, pArg, Out, Timeout, error_data);
			break;

		case LAUNCH_METHOD::LM_FakeVEH:
			Ret = SR_FakeVEH(hTargetProc, pRoutine, pArg, Out, Timeout, error_data);
			break;
		
		default:
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			Ret = SR_ERR_INVALID_LAUNCH_METHOD;
			break;
	}
		
	return Ret;
}