#include "pch.h"

#include "Start Routine.h"

DWORD StartRoutine(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, LAUNCH_METHOD Method, bool CloakThread, DWORD & Out, ERROR_DATA & error_data)
{
	DWORD Ret = 0;

	LOG("Entering StartRoutine\n");
	
	switch (Method)
	{
		case LAUNCH_METHOD::LM_NtCreateThreadEx:
			Ret = SR_NtCreateThreadEx(hTargetProc, pRoutine, pArg, CloakThread, Out, error_data);
			break;

		case LAUNCH_METHOD::LM_HijackThread:
			Ret = SR_HijackThread(hTargetProc, pRoutine, pArg, Out, error_data);
			break;

		case LAUNCH_METHOD::LM_SetWindowsHookEx:
		{
			NTSTATUS ntRet = 0;
			ULONG OwnSession	= GetSessionId(GetCurrentProcess(), ntRet);
			ULONG TargetSession = GetSessionId(hTargetProc, ntRet);

			if (TargetSession == (ULONG)-1)
			{
				INIT_ERROR_DATA(error_data, (DWORD)ntRet);

				Ret = SR_ERR_CANT_QUERY_SESSION_ID;
				break;
			}
			else if (OwnSession != 0 && OwnSession != TargetSession)
			{
				INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

				Ret = SR_ERR_NOT_LOCAL_SYSTEM;
				break;
			}
			else if (OwnSession == TargetSession)
			{
				TargetSession = (ULONG)-1;
			}
			Ret = SR_SetWindowsHookEx(hTargetProc, pRoutine, pArg, TargetSession, Out, error_data);

			break;
		}

		case LAUNCH_METHOD::LM_QueueUserAPC:
			Ret = SR_QueueUserAPC(hTargetProc, pRoutine, pArg, Out, error_data);
			break;
		
		default:
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			Ret = SR_ERR_INVALID_LAUNCH_METHOD;
			break;
	}

	LOG("End StartRoutine\n");
	
	return Ret;
}