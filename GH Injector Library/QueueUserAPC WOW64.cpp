/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

#include "pch.h"

#ifdef _WIN64

#include "Start Routine.h"

DWORD SR_QueueUserAPC_WOW64(HANDLE hTargetProc, f_Routine_WOW64 pRoutine, DWORD pArg, DWORD & Out, DWORD Timeout, ERROR_DATA & error_data)
{
	LOG(2, "Begin SR_QueueUserAPC_WOW64\n");

	BYTE Shellcode[] =
	{
		SR_REMOTE_DATA_BUFFER_86

		0x55,								// + 0x00	-> push	ebp					; x86 stack frame creation
		0x89, 0xE5,							// + 0x01	-> mov	ebp, esp

		0x53,								// + 0x03	-> push	ebx					; push ebx on stack (non volatile)
		0x8B, 0x5D, 0x08,					// + 0x04	-> mov	ebx, [ebp + 0x08]	; store pData in ebx
		0x85, 0xDB,							// + 0x07	-> test	ebx, ebx			; check if pData is valid
		0x74, 0x20,							// + 0x09	-> je	0x2B				; jump if nullptr

		0x83, 0x3B, 0x00,					// + 0x0B	-> cmp	dword ptr [ebx], 0	; test if SR_REMOTE_DATA::State is equal to SR_RS_ExecutionPending
		0x75, 0x1B,							// + 0x0E	-> jne	0x2B				; jump if not equal

		0xC6, 0x03, 0x01,					// + 0x10	-> mov	byte ptr [ebx], 1	; set SR_REMOTE_DATA::State to SR_RS_Executing

		0xFF, 0x73, 0x0C,					// + 0x13	-> push	[ebx + 0x0C]		; push pArg
		0xFF, 0x53, 0x10,					// + 0x16	-> call	[ebx + 0x10]		; call pRoutine
		0x89, 0x43, 0x04,					// + 0x19	-> mov	[ebx + 0x04], eax	; store returned value

		0x64, 0xA1, 0x18, 0x00, 0x00, 0x00,	// + 0x1C	-> mov	eax, fs:[0x18]		; GetLastError
		0x8B, 0x40, 0x34,					// + 0x22	-> mov	eax, [eax + 0x34]
		0x89, 0x43, 0x08,					// + 0x25	-> mov	[ebx + 0x08], eax	; store in SR_REMOTE_DATA::LastWin32Error

		0xC6, 0x03, 0x02,					// + 0x28	-> mov	byte ptr [ebx], 2	; set SR_REMOTE_DATA::State to SR_RS_ExecutionFinished

		0x5B,								// + 0x2B	-> pop	ebx					; restore ebx

		0x5D,								// + 0x2C	-> pop	ebp					; x86 __stdcall epilogue
		0xC2, 0x04, 0x00					// + 0x2D	-> ret	0x04
	}; // SIZE = 0x30 (+ sizeof(SR_REMOTE_DATA_WOW64))

	void * pMem = VirtualAllocEx(hTargetProc, nullptr, sizeof(Shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pMem)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "VirtualAllocEx failed: %08X\n", error_data.AdvErrorCode);

		return SR_QUAPC_ERR_CANT_ALLOC_MEM;
	}

	void * pRemoteFunc = ReCa<BYTE *>(pMem) + sizeof(SR_REMOTE_DATA_WOW64);

	auto * sr_data = ReCa<SR_REMOTE_DATA_WOW64*>(Shellcode);
	sr_data->pArg	  = pArg;
	sr_data->pRoutine = pRoutine;

	LOG(2, "Codecave allocated at %p\n", pMem);

	BOOL bRet = WriteProcessMemory(hTargetProc, pMem, Shellcode, sizeof(Shellcode), nullptr);
	if (!bRet)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_QUAPC_ERR_WPM_FAIL;
	}

	LOG(2, "Queueing APCs with:\n");
	LOG(3, "pRoutine = %08X\n", MDWD(pRemoteFunc));
	LOG(3, "pArg     = %08X\n", MDWD(pMem));

	ProcessInfo PI;
	if (!PI.SetProcess(hTargetProc))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "Can't initialize ProcessInfo class\n");

		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_QUAPC_ERR_PROC_INFO_FAIL;
	}

	bool APC_Queued = false;

	do
	{
		KWAIT_REASON reason;
		KTHREAD_STATE state;
		if (!PI.GetThreadState(state, reason) || reason == KWAIT_REASON::WrQueue)
		{
			continue;
		}

		if (!PI.IsThreadWorkerThread() && (PI.IsThreadInAlertableState_WOW64() || state == KTHREAD_STATE::Running))
		{
			DWORD ThreadID = PI.GetThreadId();
			HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, ThreadID);
			if (!hThread)
			{
				continue;
			}

			if (NT_SUCCESS(NATIVE::RtlQueueApcWow64Thread(hThread, pRemoteFunc, pMem, nullptr, nullptr)))
			{
				LOG(2, "APC queued to thread %06X\n", ThreadID);

				PostThreadMessageW(ThreadID, WM_NULL, 0, 0);
				APC_Queued = true;
			}

			CloseHandle(hThread);
		}
	} while (PI.NextThread());

	if (!APC_Queued)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "No compatible thread found\n");

		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_QUAPC_ERR_NO_THREADS;
	}

	LOG(2, "Entering wait state\n");

	Sleep(SR_REMOTE_DELAY);

	SR_REMOTE_DATA_WOW64 data{ };
	data.State			= (DWORD)SR_REMOTE_STATE::SR_RS_ExecutionPending;
	data.Ret			= ERROR_SUCCESS;
	data.LastWin32Error = ERROR_SUCCESS;

	auto Timer = GetTickCount64();
	while (GetTickCount64() - Timer < Timeout)
	{
		auto dwWaitRet = WaitForSingleObject(g_hInterruptEvent, 10);

		bRet = ReadProcessMemory(hTargetProc, pMem, &data, sizeof(data), nullptr);
		if (bRet)
		{
			if (data.State == (DWORD)SR_REMOTE_STATE::SR_RS_ExecutionFinished)
			{
				LOG(2, "Shelldata retrieved\n");

				break;
			}
		}
		else if (!bRet || dwWaitRet == WAIT_OBJECT_0)
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			if (dwWaitRet == WAIT_OBJECT_0)
			{
				LOG(2, "Interrupt!\n");

				SetEvent(g_hInterruptedEvent);

				return SR_ERR_INTERRUPT;
			}
			else
			{
				LOG(2, "ReadProcessMemory failed: %08X\n", error_data.AdvErrorCode);
			}

			if (bRet && data.State == (DWORD)SR_REMOTE_STATE::SR_RS_ExecutionPending)
			{
				data.State = (DWORD)SR_REMOTE_STATE::SR_RS_ExecutionFinished;
				WriteProcessMemory(hTargetProc, pMem, &data, sizeof(data), nullptr);
			}

			return SR_QUAPC_ERR_RPM_FAIL;
		}
	}

	if (data.State != (DWORD)SR_REMOTE_STATE::SR_RS_ExecutionFinished)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "Shell timed out\n");

		return SR_QUAPC_ERR_REMOTE_TIMEOUT;
	}

	LOG(2, "pRoutine returned: %08X\n", data.Ret);

	Out = data.Ret;

	return SR_ERR_SUCCESS;
}

#endif