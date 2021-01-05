#include "pch.h"

#ifdef _WIN64

#include "Start Routine.h"

DWORD SR_QueueUserAPC_WOW64(HANDLE hTargetProc, f_Routine_WOW64 pRoutine, DWORD pArg, DWORD & Out, DWORD Timeout, ERROR_DATA & error_data)
{
	LOG("Begin SR_QueueUserAPC_WOW64\n");

	BYTE Shellcode[] =
	{
		SR_REMOTE_DATA_BUFFER_86

		0x55,								// + 0x00	-> push	ebp						; x86 stack frame creation
		0x89, 0xE5,							// + 0x01	-> mov	ebp, esp

		0x53,								// + 0x03	-> push	ebx						; push ebx on stack (non volatile)
		0x8B, 0x5D, 0x08,					// + 0x04	-> mov	ebx, [ebp + 0x08]		; store pData in ebx
		0x85, 0xDB,							// + 0x07	-> test	ebx, ebx				; check if pData is valid
		0x74, 0x24,							// + 0x09	-> je	0x2F					; jmp to ret if not

		0x83, 0x3B, 0x00,					// + 0x0B	-> cmp	dword ptr [ebx], 0x00	; test if SR_REMOTE_DATA_WOW64::State is equal to (DWORD)SR_RS_ExecutionPending
		0x75, 0x1F,							// + 0x0E	-> jne	0x2F					; jump if not equal

		0xC6, 0x03, 0x01,					// + 0x10	-> mov	byte ptr [ebx], 1		; set SR_REMOTE_DATA::State to SR_RS_Executing

		0xFF, 0x73, 0x0C,					// + 0x13	-> push	[ebx + 0x0C]			; push pArg
		0xFF, 0x53, 0x10,					// + 0x16	-> call	[ebx + 0x10]			; call pRoutine
		0x89, 0x43, 0x04,					// + 0x19	-> mov	[ebx + 0x04], eax		; store returned value

		0x85, 0xC0,							// + 0x1C	-> test	eax, eax				; check if eax is 0 (SUCCESS)
		0x74, 0x0C,							// + 0x1E	-> je	0x2C					; jmp if equal/zero

		0x64, 0xA1, 0x18, 0x00, 0x00, 0x00,	// + 0x20	-> mov	eax, fs:[0x18]			; GetLastError
		0x8B, 0x40, 0x34,					// + 0x26	-> mov	eax, [eax + 0x34]
		0x89, 0x43, 0x08,					// + 0x29	-> mov	[ebx + 0x08], eax		; store in SR_REMOTE_DATA_WOW64::LastWin32Error

		0xC6, 0x03, 0x02,					// + 0x2C	-> mov	byte ptr [ebx], 2		; set SR_REMOTE_DATA::State to (DWORD)SR_RS_ExecutionFinished

		0x5B,								// + 0x2F	-> pop	ebx						; restore ebx
		0x5D,								// + 0x30	-> pop	ebp						; restore ebp
		0xC2, 0x04, 0x00					// + 0x31	-> ret	0x04					; return
	}; // SIZE = 0x34 (+ sizeof(SR_REMOTE_DATA_WOW64))

	void * pMem = VirtualAllocEx(hTargetProc, nullptr, sizeof(Shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pMem)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG("VirtualAllocEx failed: %08X\n", error_data.AdvErrorCode);

		return SR_QUAPC_ERR_CANT_ALLOC_MEM;
	}

	void * pRemoteFunc = ReCa<BYTE*>(pMem) + sizeof(SR_REMOTE_DATA_WOW64);

	auto * sr_data = ReCa<SR_REMOTE_DATA_WOW64*>(Shellcode);
	sr_data->pArg	  = pArg;
	sr_data->pRoutine = pRoutine;

	LOG("Codecave allocated at %p\n", pMem);

	BOOL bRet = WriteProcessMemory(hTargetProc, pMem, Shellcode, sizeof(Shellcode), nullptr);
	if (!bRet)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG("WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_QUAPC_ERR_WPM_FAIL;
	}

	LOG("Queueing APCs with\n pRoutine = %p\n pArg = %p\n", pRemoteFunc, pMem);

	ProcessInfo PI;
	if (!PI.SetProcess(hTargetProc))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG("Can't initialize ProcessInfo class\n");

		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_QUAPC_ERR_PROC_INFO_FAIL;
	}

	bool APC_Queued = false;

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
			DWORD ThreadID = PI.GetThreadId();
			HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, ThreadID);
			if (!hThread)
			{
				continue;
			}

			if (NT_SUCCESS(NATIVE::RtlQueueApcWow64Thread(hThread, pRemoteFunc, pMem, nullptr, nullptr)))
			{
				LOG("APC queued to thread %06X\n", ThreadID);

				PostThreadMessageW(ThreadID, WM_NULL, 0, 0);
				APC_Queued = true;
			}

			CloseHandle(hThread);
		}
	} while (PI.NextThread());

	if (!APC_Queued)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG("No compatible thread found\n");

		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_QUAPC_ERR_NO_THREADS;
	}

	LOG("Entering wait state\n");

	Sleep(SR_REMOTE_DELAY);

	SR_REMOTE_DATA_WOW64 data;
	data.State			= (DWORD)SR_REMOTE_STATE::SR_RS_ExecutionPending;
	data.Ret			= ERROR_SUCCESS;
	data.LastWin32Error = ERROR_SUCCESS;

	auto Timer = GetTickCount64();
	while (GetTickCount64() - Timer < Timeout)
	{
		bRet = ReadProcessMemory(hTargetProc, pMem, &data, sizeof(data), nullptr);
		if (bRet)
		{
			if (data.State == (DWORD)SR_REMOTE_STATE::SR_RS_ExecutionFinished)
			{
				LOG("Shelldata retrieved\n");

				break;
			}
		}
		else
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG("ReadProcessMemory failed: %08X\n", error_data.AdvErrorCode);

			return SR_QUAPC_ERR_RPM_FAIL;
		}

		Sleep(10);
	}

	if (data.State != (DWORD)SR_REMOTE_STATE::SR_RS_ExecutionFinished)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG("Shell timed out\n");

		return SR_QUAPC_ERR_REMOTE_TIMEOUT;
	}

	LOG("pRoutine returned: %08X\n", data.Ret);

	Out = data.Ret;

	LOG("End SR_QueueUserAPC\n");

	return SR_ERR_SUCCESS;
}

#endif