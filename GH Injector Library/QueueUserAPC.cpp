#include "pch.h"

#include "Start Routine.h"

DWORD SR_QueueUserAPC(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD & Out, DWORD Timeout, ERROR_DATA & error_data)
{
	LOG("Begin SR_QueueUserAPC\n");

#ifdef _WIN64

	BYTE Shellcode[] =
	{
		SR_REMOTE_DATA_BUFFER_64

		0x48, 0x85, 0xC9,										// + 0x00	-> test	rcx, rcx				; check if pData is valid
		0x74, 0x3D,												// + 0x03	-> je	0x42					; jmp to ret if not

		0x53,													// + 0x05	-> push rbx						; push rbx on stack (non volatile)
		0x48, 0x8B, 0xD9,										// + 0x06	-> mov	rbx, rcx				; store pArg in rbx
		0x83, 0x3B, 0x00,										// + 0x09	-> cmp	dword ptr [rbx], 0x00	; test if SR_REMOTE_DATA::State is equal to SR_RS_ExecutionPending
		0x75, 0x33,												// + 0x0C	-> jne	0x41					; jump if not equal

		0xC7, 0x03, 0x01, 0x00, 0x00, 0x00,						// + 0x0E	-> mov	[rbx], 1				; set SR_REMOTE_DATA::State to SR_RS_Executing

		0x48, 0x8B, 0x4B, 0x18,									// + 0x14	-> mov  rcx, [rbx + 0x18]		; move pArg into rcx
		0x48, 0x83, 0xEC, 0x20,									// + 0x18	-> sub	rsp, 0x20				; reserve stack
		0xFF, 0x53, 0x20,										// + 0x1C	-> call qword ptr [rbx + 0x20]	; call pRoutine
		0x48, 0x83, 0xC4, 0x20,									// + 0x1F	-> add	rsp, 0x20				; update stack
		0x48, 0x89, 0x43, 0x08,									// + 0x23	-> mov	[rbx + 0x08], rax		; store returned value

		0x48, 0x85, 0xC0,										// + 0x27	-> test rax, rax				; check if rax is 0 (SUCCESS)
		0x74, 0x0F,												// + 0x2A	-> je	0x3B					; jmp if equal/zero

		0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,	// + 0x2C	-> mov	rax, gs:[0x30]			; GetLastError
		0x8B, 0x40, 0x68,										// + 0x35	-> mov	eax, [rax + 0x68]
		0x89, 0x43, 0x10,										// + 0x38	-> mov	[rbx + 0x10], eax		; store in SR_REMOTE_DATA::LastWin32Error

		0xC7, 0x03, 0x02, 0x00, 0x00, 0x00,						// + 0x3B	-> mov	[rbx], 2				; set SR_REMOTE_DATA::State to SR_RS_ExecutionFinished

		0x5B,													// + 0x41	-> pop	rbx						; restore rbx

		0xC3													// + 0x42	-> ret							; return
	}; // SIZE = 0x43 (+ sizeof(SR_REMOTE_DATA))

#else

	BYTE Shellcode[] =
	{
		SR_REMOTE_DATA_BUFFER_86

		0x55,								// + 0x00	-> push	ebp						; x86 stack frame creation
		0x89, 0xE5,							// + 0x01	-> mov	ebp, esp

		0x53,								// + 0x03	-> push	ebx						; push ebx on stack (non volatile)
		0x8B, 0x5D, 0x08,					// + 0x04	-> mov	ebx, [ebp + 0x08]		; store pData in ebx
		0x85, 0xDB,							// + 0x07	-> test	ebx, ebx				; check if pData is valid
		0x74, 0x24,							// + 0x09	-> je	0x2F					; jmp to ret if not

		0x83, 0x3B, 0x00,					// + 0x0B	-> cmp	dword ptr [ebx], 0x00	; test if SR_REMOTE_DATA::State is equal to SR_RS_ExecutionPending
		0x75, 0x1F,							// + 0x0E	-> jne	0x2F					; jump if not equal

		0xC6, 0x03, 0x01,					// + 0x10	-> mov	byte ptr [ebx], 1		; set SR_REMOTE_DATA::State to SR_RS_Executing

		0xFF, 0x73, 0x0C,					// + 0x13	-> push	[ebx + 0x0C]			; push pArg
		0xFF, 0x53, 0x10,					// + 0x16	-> call	[ebx + 0x10]			; call pRoutine
		0x89, 0x43, 0x04,					// + 0x19	-> mov	[ebx + 0x04], eax		; store returned value

		0x85, 0xC0,							// + 0x1C	-> test	eax, eax				; check if eax is 0 (SUCCESS)
		0x74, 0x0C,							// + 0x1E	-> je	0x27					; jmp if equal/zero

		0x64, 0xA1, 0x18, 0x00, 0x00, 0x00,	// + 0x20	-> mov	eax, fs:[0x18]			; GetLastError
		0x8B, 0x40, 0x34,					// + 0x26	-> mov	eax, [eax + 0x34]
		0x89, 0x43, 0x08,					// + 0x29	-> mov	[ebx + 0x08], eax		; store in SR_REMOTE_DATA::LastWin32Error

		0xC6, 0x03, 0x02,					// + 0x2C	-> mov	byte ptr [ebx], 2		; set SR_REMOTE_DATA::State to SR_RS_ExecutionFinished

		0x5B,								// + 0x3F	-> pop	ebx						; restore ebx
		0x5D,								// + 0x30	-> pop	ebp						; restore ebp
		0xC2, 0x04, 0x00					// + 0x31	-> ret	0x04					; return
	}; // SIZE = 0x34 (+ sizeof(SR_REMOTE_DATA))

#endif

	void * pMem = VirtualAllocEx(hTargetProc, nullptr, sizeof(Shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pMem)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG("VirtualAllocEx failed: %08X\n", error_data.AdvErrorCode);

		return SR_QUAPC_ERR_CANT_ALLOC_MEM;
	}

	void * pRemoteFunc = ReCa<BYTE*>(pMem) + sizeof(SR_REMOTE_DATA);

	auto * sr_data = ReCa<SR_REMOTE_DATA*>(Shellcode);
	sr_data->pArg		= pArg;
	sr_data->pRoutine	= pRoutine;

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
		
		if ((!PI.IsThreadWorkerThread() && (PI.IsThreadInAlertableState() || state == THREAD_STATE::Running)) && PI.GetThreadId() != GetCurrentThreadId())
		{
			DWORD ThreadID = PI.GetThreadId();
			HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, ThreadID);
			if (!hThread)
			{
				continue;
			}

			if (QueueUserAPC(ReCa<PAPCFUNC>(pRemoteFunc), hThread, ReCa<ULONG_PTR>(pMem)))
			{
				LOG("APC queued to thread %06X\n", ThreadID);

				PostThreadMessageW(ThreadID, WM_NULL, 0, 0);
				APC_Queued = true;
			}

			CloseHandle(hThread);
		}
	}
	while (PI.NextThread());

	if (!APC_Queued)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG("No compatible thread found\n");

		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_QUAPC_ERR_NO_THREADS;
	}

	LOG("Entering wait state\n");

	Sleep(SR_REMOTE_DELAY);

	SR_REMOTE_DATA data;
	data.State			= SR_REMOTE_STATE::SR_RS_ExecutionPending;
	data.Ret			= ERROR_SUCCESS;
	data.LastWin32Error = ERROR_SUCCESS;

	auto Timer = GetTickCount64();
	while (GetTickCount64() - Timer < Timeout)
	{
		bRet = ReadProcessMemory(hTargetProc, pMem, &data, sizeof(data), nullptr);
		if (bRet)
		{
			if (data.State == SR_REMOTE_STATE::SR_RS_ExecutionFinished)
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

	if (data.State != SR_REMOTE_STATE::SR_RS_ExecutionFinished)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG("Shell timed out\n");

		return SR_QUAPC_ERR_REMOTE_TIMEOUT;
	}

	LOG("pRoutine returned: %08X\n", data.Ret);

	Out	= data.Ret;

	LOG("End SR_QueueUserAPC\n");
		
	return SR_ERR_SUCCESS;
}