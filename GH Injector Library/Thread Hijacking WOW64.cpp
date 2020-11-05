#include "pch.h"

#ifdef _WIN64

#include "Start Routine.h"

DWORD SR_HijackThread_WOW64(HANDLE hTargetProc, f_Routine_WOW64 pRoutine, DWORD pArg, DWORD & Out, DWORD Timeout, ERROR_DATA & error_data)
{
	ProcessInfo PI;
	if (!PI.SetProcess(hTargetProc))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return SR_HT_ERR_PROC_INFO_FAIL;
	}

	DWORD ThreadID = 0;

	do
	{
		KWAIT_REASON reason;
		THREAD_STATE state;
		if (!PI.GetThreadState(state, reason) || reason == KWAIT_REASON::WrQueue)
		{
			continue;
		}		

		if (!PI.IsThreadWorkerThread() && (PI.IsThreadInAlertableState_WOW64() || state == THREAD_STATE::Running))
		{
			ThreadID = PI.GetThreadId();
			break;
		}

	} while (PI.NextThread());

	if (!ThreadID)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return SR_HT_ERR_NO_THREADS;
	}

	HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, ThreadID);
	if (!hThread)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		return SR_HT_ERR_OPEN_THREAD_FAIL;
	}

	if (SuspendThread(hThread) == (DWORD)-1)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		CloseHandle(hThread);

		return SR_HT_ERR_SUSPEND_FAIL;
	}

	WOW64_CONTEXT OldContext{ 0 };
	OldContext.ContextFlags = CONTEXT_CONTROL;

	if (!Wow64GetThreadContext(hThread, &OldContext))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		ResumeThread(hThread);
		CloseHandle(hThread);

		return SR_HT_ERR_GET_CONTEXT_FAIL;
	}

	void * pMem = VirtualAllocEx(hTargetProc, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pMem)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		CloseHandle(hThread);

		return SR_HT_ERR_CANT_ALLOC_MEM;
	}

	BYTE Shellcode[] =
	{
		SR_REMOTE_DATA_BUFFER_86

		0x83, 0xEC, 0x04,							// + 0x00				-> sub	esp, 0x04							; prepare stack for ret
		0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,	// + 0x03 (+ 0x06)		-> mov	[esp], OldEip						; store old eip as return address

		0x50, 0x51, 0x52, 0x53,						// + 0x0A				-> push e(a/c/d/b)							; save e(a/c/d/b)x
		0x9C,										// + 0x0E				-> pushfd									; save flags register

		0xBB, 0x00, 0x00, 0x00, 0x00,				// + 0x0F (+ 0x10)		-> mov	ebx, 0x00000000						; move pData into ebx (update address manually on runtime)

		0xC6, 0x03, 0x01,							// + 0x14				-> mov  byte ptr [ebx], 1					; set SR_REMOTE_DATA::State to SR_RS_Executing

		0xFF, 0x73, 0x0C,							// + 0x17				-> push [ebx + 0x0C]						; push pArg
		0xFF, 0x53, 0x10,							// + 0x1A				-> call dword ptr [ebx + 0x10]				; call pRoutine
		0x89, 0x43, 0x04,							// + 0x1D				-> mov	[ebx + 0x04], eax					; store returned value

		0x85, 0xC0,									// + 0x20				-> test eax, eax							; check if eax is 0 (SUCCESS)
		0x74, 0x0C,									// + 0x22				-> je	0x30								; jmp if equal/zero

		0x6A, 0xA1, 0x18, 0x00, 0x00, 0x00,			// + 0x24				-> mov	eax, fs:[0x18]						; GetLastError
		0x8B, 0x40, 0x34,							// + 0x2A				-> mov	eax, [eax + 0x34]
		0x89, 0x43, 0x08,							// + 0x2D				-> mov	[ebx + 0x08], eax					; store in SR_REMOTE_DATA::LastWin32Error

		0xC7, 0x03, 0x02, 0x00, 0x00, 0x00,			// + 0x30				-> mov	byte ptr [ebx], 2					; set SR_REMOTE_DATA::State to SR_RS_ExecutionFinished

		0x9D,										// + 0x36				-> popfd									; restore flags register
		0x5B, 0x5A, 0x59, 0x58,						// + 0x37				-> pop e(d/c/a)								; restore e(b/d/c/a)x

		0xC3										// + 0x3B				-> ret										; return to OldEip
	}; // SIZE = 0x3C (+ 0x04)

	auto OldEIP = OldContext.Eip;
	*ReCa<DWORD*>(Shellcode + 0x06 + sizeof(SR_REMOTE_DATA_WOW64)) = OldEIP;
	*ReCa<DWORD*>(Shellcode + 0x10 + sizeof(SR_REMOTE_DATA_WOW64)) = MDWD(pMem);

	void * pRemoteFunc	= ReCa<BYTE*>(pMem) + sizeof(SR_REMOTE_DATA_WOW64);
	OldContext.Eip		= MDWD(pRemoteFunc);

	auto * sr_data = ReCa<SR_REMOTE_DATA_WOW64*>(Shellcode);
	sr_data->pArg		= pArg;
	sr_data->pRoutine	= pRoutine;

	if (!WriteProcessMemory(hTargetProc, pMem, Shellcode, sizeof(Shellcode), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		ResumeThread(hThread);
		CloseHandle(hThread);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_HT_ERR_WPM_FAIL;
	}

	if (!Wow64SetThreadContext(hThread, &OldContext))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		ResumeThread(hThread);
		CloseHandle(hThread);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_HT_ERR_SET_CONTEXT_FAIL;
	}

	if (ResumeThread(hThread) == (DWORD)-1)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		OldContext.Eip = OldEIP;
		Wow64SetThreadContext(hThread, &OldContext);
		ResumeThread(hThread);

		CloseHandle(hThread);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_HT_ERR_RESUME_FAIL;
	}

	PostThreadMessageW(ThreadID, WM_NULL, 0, 0);

	SR_REMOTE_DATA_WOW64 data;
	data.State			= (DWORD)SR_REMOTE_STATE::SR_RS_ExecutionPending;
	data.Ret			= ERROR_SUCCESS;
	data.LastWin32Error = ERROR_SUCCESS;

	auto Timer = GetTickCount64();
	while (GetTickCount64() - Timer < Timeout)
	{
		if (ReadProcessMemory(hTargetProc, pMem, &data, sizeof(data), nullptr))
		{
			if (data.State == (DWORD)SR_REMOTE_STATE::SR_RS_ExecutionFinished)
			{
				break;
			}
		}

		Sleep(10);
	}

	if (data.State != (DWORD)SR_REMOTE_STATE::SR_RS_ExecutionFinished)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		if (data.State == (DWORD)SR_REMOTE_STATE::SR_RS_ExecutionPending)
		{
			if (SuspendThread(hThread) != (DWORD)-1)
			{
				OldContext.Eip = OldEIP;

				if (Wow64SetThreadContext(hThread, &OldContext) && ResumeThread(hThread) != (DWORD)-1)
				{
					CloseHandle(hThread);

					VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

					return SR_HT_ERR_REMOTE_PENDING_TIMEOUT;
				}
			}
		}

		CloseHandle(hThread);

		return SR_HT_ERR_REMOTE_TIMEOUT;
	}

	CloseHandle(hThread);
	VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

	Out = data.Ret;
	
	return SR_ERR_SUCCESS;
}

#endif