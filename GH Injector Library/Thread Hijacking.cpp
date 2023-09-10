/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

#include "pch.h"

#include "Start Routine.h"

DWORD SR_HijackThread(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD & Out, DWORD Timeout, ERROR_DATA & error_data)
{
	LOG(2, "Begin SR_HijackThread\n");

	ProcessInfo PI;
	if (!PI.SetProcess(hTargetProc))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "Can't initialize ProcessInfo class\n");

		return SR_HT_ERR_PROC_INFO_FAIL;
	}

	DWORD ThreadID = 0;

	do
	{
		KWAIT_REASON reason;
		KTHREAD_STATE state;
		if (!PI.GetThreadState(state, reason) || reason == KWAIT_REASON::WrQueue)
		{
			continue;
		}

		if ((!PI.IsThreadWorkerThread() && (PI.IsThreadInAlertableState() || state == KTHREAD_STATE::Running)) && PI.GetThreadId() != GetCurrentThreadId())
		{
			ThreadID = PI.GetThreadId();
			break;
		}

	}
	while (PI.NextThread());
	
	if (!ThreadID)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "No compatible thread found\n");

		return SR_HT_ERR_NO_THREADS;
	}

	LOG(2, "Target thread %06X\n", ThreadID);

	HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, ThreadID);
	if (!hThread)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "OpenThread failed: %08X\n", error_data.AdvErrorCode);

		return SR_HT_ERR_OPEN_THREAD_FAIL;
	}

	if (SuspendThread(hThread) == (DWORD)-1)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "SuspendThread failed: %08X\n", error_data.AdvErrorCode);

		CloseHandle(hThread);

		return SR_HT_ERR_SUSPEND_FAIL;
	}

	LOG(2, "Target thread suspended\n");

	CONTEXT OldContext{ 0 };
	OldContext.ContextFlags = CONTEXT_CONTROL;

	if (!GetThreadContext(hThread, &OldContext))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "GetThreadContext failed: %08X\n", error_data.AdvErrorCode);

		ResumeThread(hThread);
		CloseHandle(hThread);

		return SR_HT_ERR_GET_CONTEXT_FAIL;
	}

	void * pMem = VirtualAllocEx(hTargetProc, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pMem)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "VirtualAllocEx failed: %08X\n", error_data.AdvErrorCode);

		CloseHandle(hThread);

		return SR_HT_ERR_CANT_ALLOC_MEM;
	}
	
	/*
		__declspec(naked) void ThreadHijack_Shell()
		{
			//Stack setup
			//Save registers

			SR_REMOTE_DATA * data = ReCa<SR_REMOTE_DATA *>(ReCa<BYTE *>(ThreadHijack_Shell) - sizeof(SR_REMOTE_DATA));
			data->State = SR_REMOTE_STATE::SR_RS_Executing;

			data->Ret = data->pRoutine(data->pArg);
			data->LastWin32Error = GetLastError();
			data->State = SR_REMOTE_STATE::SR_RS_ExecutionFinished;

			//Restore stack
			//Restore registers

			//Return to hijacked code
		}
	*/

#ifdef _WIN64
	
	BYTE Shellcode[] =
	{
		SR_REMOTE_DATA_BUFFER

		0x48, 0x83, 0xEC, 0x08,													// + 0x00			-> sub	rsp, 0x08				; prepare stack for ret
		0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,								// + 0x04 (+ 0x07)	-> mov	[rsp + 0x00], RipLo		; store old rip as return address
		0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00,							// + 0x0B (+ 0x0F)	-> mov	[rsp + 0x04], RipHi		; 

		0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,		// + 0x13			-> push	r(a/c/d)x / r (8 - 11)	; save volatile registers
		0x9C,																	// + 0x1E			-> pushfq						; save flags register

		0x53,																	// + 0x1F			-> push rbx						; push rbx on stack (non volatile)
		0x48, 0x8D, 0x1D, 0xA9, 0xFF, 0xFF, 0xFF,								// + 0x20			-> lea	rbx, [-0x30]			; load pData into rbx

		0xC6, 0x03, 0x01,														// + 0x27			-> mov	byte ptr [rbx], 1		; set SR_REMOTE_DATA::State to SR_RS_Executing

		0x55,																	// + 0x2A			-> push rbp						; store rbp
		0x48, 0x8B, 0xEC,														// + 0x2B			-> mov	rbp, rsp				; save rsp to rbp
		0x48, 0x83, 0xE4, 0xF0,													// + 0x2E			-> and	rsp, -0x10				; 16-bit align rsp

		0x48, 0x8B, 0x4B, 0x18,													// + 0x32			-> mov  rcx, [rbx + 0x18]		; move pArg into rcx
		0x48, 0x83, 0xEC, 0x20,													// + 0x36			-> sub	rsp, 0x20				; reserve stack
		0xFF, 0x53, 0x20, 														// + 0x3A			-> call qword ptr [rbx + 0x20]	; call pRoutine
		0x48, 0x83, 0xC4, 0x20, 												// + 0x3D			-> add	rsp, 0x20				; update stack
		0x48, 0x89, 0x43, 0x08,													// + 0x41			-> mov	[rbx + 0x08], rax		; store returned value
		
		0x48, 0x8B, 0xE5,														// + 0x45			-> mov	rsp, rbp				; restore rsp
		0x5D,																	// + 0x48			-> pop	rbp						; restore rbp

		0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,					// + 0x49			-> mov	rax, gs:[0x30]			; GetLastError
		0x8B, 0x40, 0x68,														// + 0x52			-> mov	eax, [rax + 0x68]
		0x89, 0x43, 0x10,														// + 0x55			-> mov	[rbx + 0x10], eax		; store in SR_REMOTE_DATA::LastWin32Error

		0xC6, 0x03, 0x02,														// + 0x58			-> mov	byte ptr [rbx], 2		; set SR_REMOTE_DATA::State to SR_RS_ExecutionFinished

		0x5B,																	// + 0x5B			-> pop rbx						; restore rbx

		0x9D,																	// + 0x5C			-> popfq						; restore flags register
		0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58,		// + 0x5D			-> pop r(11-8) / r(d/c/a)x		; restore volatile registers

		0xC3																	// + 0x68			-> ret							; return to old rip and continue execution
	}; // SIZE = 0x69 (+ sizeof(SR_REMOTE_DATA))

	auto OldRIP = OldContext.Rip;
	DWORD dwLoRIP = (DWORD)((OldRIP		   ) & 0xFFFFFFFF);
	DWORD dwHiRIP = (DWORD)((OldRIP >> 0x20) & 0xFFFFFFFF);

	*ReCa<DWORD *>(Shellcode + 0x07 + sizeof(SR_REMOTE_DATA)) = dwLoRIP;
	*ReCa<DWORD *>(Shellcode + 0x0F + sizeof(SR_REMOTE_DATA)) = dwHiRIP;

	void * pRemoteFunc	= ReCa<BYTE *>(pMem) + sizeof(SR_REMOTE_DATA);
	OldContext.Rip		= ReCa<ULONG_PTR>(pRemoteFunc);

#else

	BYTE Shellcode[] =
	{
		SR_REMOTE_DATA_BUFFER

		0x83, 0xEC, 0x04,							// + 0x00				-> sub	esp, 0x04							; prepare stack for ret
		0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,	// + 0x03 (+ 0x06)		-> mov	[esp], OldEip						; store old eip as return address

		0x50, 0x51, 0x52, 0x53,						// + 0x0A				-> push e(a/c/d/b)							; save e(a/c/d/b)x
		0x9C,										// + 0x0E				-> pushfd									; save flags register

		0xBB, 0x00, 0x00, 0x00, 0x00,				// + 0x0F (+ 0x10)		-> mov	ebx, 0x00000000						; move pData into ebx (update address manually on runtime)

		0xC6, 0x03, 0x01,							// + 0x14				-> mov  byte ptr [ebx], 1					; set SR_REMOTE_DATA::State to SR_RS_Executing

		0xFF, 0x73, 0x0C,							// + 0x17				-> push [ebx + 0x0C]						; push pArg
		0xFF, 0x53, 0x10,							// + 0x1A				-> call dword ptr [ebx + 0x10]				; call pRoutine
		0x89, 0x43, 0x04,							// + 0x1D				-> mov	[ebx + 0x04], eax					; store returned value

		0x64, 0xA1, 0x18, 0x00, 0x00, 0x00,			// + 0x20				-> mov	eax, fs:[0x18]						; GetLastError
		0x8B, 0x40, 0x34,							// + 0x26				-> mov	eax, [eax + 0x34]
		0x89, 0x43, 0x08,							// + 0x29				-> mov	[ebx + 0x08], eax					; store in SR_REMOTE_DATA::LastWin32Error

		0xC7, 0x03, 0x02, 0x00, 0x00, 0x00,			// + 0x2C				-> mov	byte ptr [ebx], 2					; set SR_REMOTE_DATA::State to SR_RS_ExecutionFinished
		
		0x9D,										// + 0x32				-> popfd									; restore flags register
		0x5B, 0x5A, 0x59, 0x58,						// + 0x33				-> pop e(d/c/a)								; restore e(b/d/c/a)x
		
		0xC3										// + 0x37				-> ret										; return to OldEip
	}; // SIZE = 0x38 (+ sizeof(SR_REMOTE_DATA))

	auto OldEIP = OldContext.Eip;
	*ReCa<DWORD *>(Shellcode + 0x06 + sizeof(SR_REMOTE_DATA)) = OldEIP;
	*ReCa<void **>(Shellcode + 0x10 + sizeof(SR_REMOTE_DATA)) = pMem;

	void * pRemoteFunc	= ReCa<BYTE *>(pMem) + sizeof(SR_REMOTE_DATA);
	OldContext.Eip		= ReCa<DWORD>(pRemoteFunc);

#endif

	LOG(2, "Shellcode prepared\n");

	auto * sr_data = ReCa<SR_REMOTE_DATA *>(Shellcode);
	sr_data->pArg		= pArg;
	sr_data->pRoutine	= pRoutine;

	LOG(2, "Hijacking thread with:\n");
	LOG(3, "pRoutine = %p\n", pRemoteFunc);
	LOG(3, "pArg     = %p\n", pMem);

	if (!WriteProcessMemory(hTargetProc, pMem, Shellcode, sizeof(Shellcode), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		ResumeThread(hThread);
		CloseHandle(hThread);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_HT_ERR_WPM_FAIL;
	}

	if (!SetThreadContext(hThread, &OldContext))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "SetThreadContext failed: %08X\n", error_data.AdvErrorCode);

		ResumeThread(hThread);
		CloseHandle(hThread);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_HT_ERR_SET_CONTEXT_FAIL;
	}

#ifdef _WIN64
	LOG(2, "RIP replaced\n");
#else
	LOG(2, "EIP replaced\n");
#endif

	if (ResumeThread(hThread) == (DWORD)-1)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "ResumeThread failed: %08X\n", error_data.AdvErrorCode);

#ifdef _WIN64
		OldContext.Rip = OldRIP;
#else
		OldContext.Eip = OldEIP;
#endif
		SetThreadContext(hThread, &OldContext);
		ResumeThread(hThread);

		CloseHandle(hThread);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_HT_ERR_RESUME_FAIL;
	}

	LOG(2, "Thread resumed\n");

	PostThreadMessageW(ThreadID, WM_NULL, 0, 0);

	Sleep(SR_REMOTE_DELAY);

	SR_REMOTE_DATA data{ };
	data.State			= SR_REMOTE_STATE::SR_RS_ExecutionPending;
	data.Ret			= ERROR_SUCCESS;
	data.LastWin32Error = ERROR_SUCCESS;

	LOG(2, "Entering wait state\n");

	auto Timer = GetTickCount64();
	while (GetTickCount64() - Timer < Timeout)
	{
		auto dwWaitRet = WaitForSingleObject(g_hInterruptEvent, 10);

		BOOL bRet = ReadProcessMemory(hTargetProc, pMem, &data, sizeof(data), nullptr);
		if (bRet && data.State == SR_REMOTE_STATE::SR_RS_ExecutionFinished)
		{
			LOG(2, "Shelldata retrieved\n");

			break;
		}
		else if (!bRet || dwWaitRet == WAIT_OBJECT_0)
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			if (dwWaitRet == WAIT_OBJECT_0)
			{
				LOG(2, "Interrupt!\n");
			}
			else
			{
				LOG(2, "ReadProcessMemory failed: %08X\n", error_data.AdvErrorCode);
			}

			if (bRet && data.State == SR_REMOTE_STATE::SR_RS_ExecutionPending && SuspendThread(hThread) != (DWORD)-1)
			{
#ifdef _WIN64
				OldContext.Rip = OldRIP;
#else
				OldContext.Eip = OldEIP;
#endif
				if (SetThreadContext(hThread, &OldContext) && ResumeThread(hThread) != (DWORD)-1)
				{
					ResumeThread(hThread);

					CloseHandle(hThread);
					
					VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);
				}
			}

			if (dwWaitRet == WAIT_OBJECT_0)
			{
				SetEvent(g_hInterruptedEvent);

				return SR_ERR_INTERRUPT;
			}

			return SR_HT_ERR_RPM_FAIL;
		}
	}

	if (data.State != SR_REMOTE_STATE::SR_RS_ExecutionFinished)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		if (data.State == SR_REMOTE_STATE::SR_RS_ExecutionPending)
		{
			if (SuspendThread(hThread) != (DWORD)-1)
			{
				LOG(2, "Shell timed out\n");

#ifdef _WIN64
				OldContext.Rip = OldRIP;
#else
				OldContext.Eip = OldEIP;
#endif
				if (SetThreadContext(hThread, &OldContext) && ResumeThread(hThread) != (DWORD)-1)
				{
					CloseHandle(hThread);

					VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

					return SR_HT_ERR_REMOTE_PENDING_TIMEOUT;
				}
			}
		}

		LOG(2, "pRoutine timed out\n");

		CloseHandle(hThread);

		return SR_HT_ERR_REMOTE_TIMEOUT;
	}

	CloseHandle(hThread);

	VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

	LOG(2, "pRoutine returned: %08X\n", data.Ret);

	Out	= data.Ret;

	return SR_ERR_SUCCESS;
}