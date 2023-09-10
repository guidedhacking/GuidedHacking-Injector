/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

#include "pch.h"

#include "Start Routine.h"

DWORD SR_NtCreateThreadEx(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD Flags, DWORD & Out, DWORD Timeout, ERROR_DATA & error_data)
{
	LOG(2, "Begin SR_NtCreateThreadEx\n");

	ProcessInfo pi;
	void * pEntrypoint	= nullptr;
	DWORD FakeTID		= 0;

	if (Flags & (INJ_CTF_FAKE_START_ADDRESS | INJ_CTF_FAKE_TEB_CLIENT_ID))
	{
		LOG(2, "Thread cloaking specified\n");

		if (!pi.SetProcess(hTargetProc))
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(2, "Can't initialize ProcessInfo class\n");

			return SR_NTCTE_ERR_PROC_INFO_FAIL;
		}

		pEntrypoint = pi.GetEntrypoint();
		if (pEntrypoint == nullptr)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(2, "Failed to resolve entrypoint\n");

			return SR_NTCTE_ERR_GET_ENTRYPOINT;
		}

		FakeTID = pi.GetThreadId();
	}

	DWORD ntFlags	= NULL;
	HANDLE hThread	= nullptr;

	bool FakeStartAddress	= false;
	bool FakeClientId		= false;

	if (Flags & INJ_CTF_FAKE_START_ADDRESS)
	{
		FakeStartAddress = true;
		ntFlags |= THREAD_CREATE_FLAGS_CREATE_SUSPENDED;
	}

	if (Flags & INJ_CTF_HIDE_FROM_DEBUGGER)
	{
		ntFlags |= THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
	}

	if (Flags & INJ_CTF_SKIP_THREAD_ATTACH)
	{
		ntFlags |= THREAD_CREATE_FLAGS_CREATE_SUSPENDED;
		//ntFlags |= THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH;
	}

	if (Flags & INJ_CTF_FAKE_TEB_CLIENT_ID)
	{
		FakeClientId = true;
	}

	/*
		DWORD __stdcall Thread_Shell(void * lpThreadParameter)
		{
			SR_REMOTE_DATA * data = ReCa<SR_REMOTE_DATA *>(lpThreadParameter);

			if (data != nullptr)
			{
				if (data->Buffer)
				{
					#ifdef _WIN64
						TEB * teb = (TEB *)__readfsdword(0x18);
					#else
						TEB * teb = (TEB *)__readgsgword(0x30);
					#endif

					auto buffer = teb->ClientID.UniqueThreadID;
					teb->ClientId.UniqueThread = (void *)data->Buffer;
					data->Buffer = (UINT_PTR)buffer;
				}

				data->State = SR_REMOTE_STATE::SR_RS_Executing;

				data->Ret = data->pRoutine(data->pArg);
				data->LastWin32Error = GetLastError();

				data->State = SR_REMOTE_STATE::SR_RS_ExecutionFinished;

				if (data->Buffer)
				{
					#ifdef _WIN64
						TEB * teb = (TEB *)__readfsdword(0x18);
					#else
						TEB * teb = (TEB *)__readgsgword(0x30);
					#endif

					teb->ClientID.UniqueThread = (void *)data->Buffer;
				}
			}
			else
			{
				return (DWORD)-1;
			}

			return ERROR_SUCCESS;
		}
	*/

#ifdef _WIN64

	BYTE Shellcode[] =
	{
		SR_REMOTE_DATA_BUFFER

		0x48, 0x85, 0xC9,										// + 0x00	-> test	rcx, rcx					; check if pData is valid
		0x74, 0x5B,												// + 0x03	-> je	0x60						; jmp to ret if not and set eax to -1

		0x53,													// + 0x05	-> push rbx							; push rbx on stack (non volatile)
		0x48, 0x8B, 0xD9,										// + 0x06	-> mov	rbx, rcx					; store pArg in rbx
		0xC6, 0x03, 0x01,										// + 0x09	-> mov	byte ptr [rbx], 1			; set SR_REMOTE_DATA::State to SR_RS_Executing

		0x83, 0x7B, 0x28, 0x00,									// + 0x0C	-> cmp  dword ptr [rbx + 0x28], 0	; check if SR_REMOTE_DATA::Buffer is 0 (fake TID)
		0x74, 0x11,												// + 0x10	-> je   0x23						; skip if no fake TID has been provided
		0x48, 0x8B, 0x53, 0x28,									// + 0x12	-> mov  rdx, [rbx + 0x28]			; load fake thread ID
		0x65, 0x48, 0x87, 0x14, 0x25, 0x48, 0x00, 0x00, 0x00,	// + 0x16	-> xchg gs:[0x48], rdx				; set fake thread ID and grab real thread ID
		0x48, 0x89, 0x53, 0x28,									// + 0x1F	-> mov  [rbx + 0x28], rdx			; set SR_REMOTE_DATA::Buffer to the real thread ID

		0x48, 0x8B, 0x4B, 0x18,									// + 0x23	-> mov  rcx, [rbx + 0x18]			; move pArg into rcx
		0x48, 0x83, 0xEC, 0x20,									// + 0x27	-> sub	rsp, 0x20					; reserve stack
		0xFF, 0x53, 0x20,										// + 0x2B	-> call qword ptr [rbx + 0x20]		; call pRoutine
		0x48, 0x83, 0xC4, 0x20,									// + 0x2E	-> add	rsp, 0x20					; update stack
		0x48, 0x89, 0x43, 0x08,									// + 0x32	-> mov	[rbx + 0x08], rax			; store returned value

		0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,	// + 0x36	-> mov	rax, gs:[0x30]				; GetLastError
		0x8B, 0x40, 0x68,										// + 0x3F	-> mov	eax, [rax + 0x68]
		0x89, 0x43, 0x10,										// + 0x42	-> mov	[rbx + 0x10], eax			; store in SR_REMOTE_DATA::LastWin32Error

		0x83, 0x7B, 0x28, 0x00,									// + 0x45	-> cmp  dword ptr [rbx + 0x28], 0	; check if SR_REMOTE_DATA::Buffer is 0 (real TID)
		0x74, 0x0D,												// + 0x49	-> je   0x58						; skip if no TID was saved
		0x48, 0x8B, 0x53, 0x28,									// + 0x4B	-> mov  rdx, [rbx + 0x28]			; load real thread ID
		0x65, 0x48, 0x89, 0x14, 0x25, 0x48, 0x00, 0x00, 0x00,	// + 0x4F	-> mov  gs:[0x48], rdx				; move real thread ID back into TEB

		0xC6, 0x03, 0x02,										// + 0x58	-> mov	byte ptr [rbx], 2			; set SR_REMOTE_DATA::State to SR_RS_ExecutionFinished
		0x5B,													// + 0x5B	-> pop	rbx							; restore rbx

		0x31, 0xC0,												// + 0x5C	-> xor	rax, rax					; zero eax (thread exitcode = 0)
		0xEB, 0x03,												// + 0x5E	-> jmp	0x63						; jmp to ret

		0x83, 0xC8, 0xFF,										// + 0x60	-> or rax, -1						; set eax to -1 (thread exitcode = -1)

		0xC3													// + 0x63	-> ret								; return
	}; // SIZE = 0x64 (+ sizeof(SR_REMOTE_DATA))

#else

	BYTE Shellcode[] =
	{
		SR_REMOTE_DATA_BUFFER

		0x55,										// + 0x00	-> push	ebp							; x86 stack frame creation
		0x89, 0xE5,									// + 0x01	-> mov	ebp, esp

		0x53,										// + 0x03	-> push	ebx							; push ebx on stack (non volatile)
		0x8B, 0x5D, 0x08,							// + 0x04	-> mov	ebx, [ebp + 0x08]			; store pData in ebx
		0x85, 0xDB,									// + 0x07	-> test	ebx, ebx					; check if pData is valid
		0x74, 0x42,									// + 0x09	-> je	0x4D						; jmp to ret if not and set eax to -1

		0xC6, 0x03, 0x01,							// + 0x0B	-> mov	byte ptr [ebx], 1			; set SR_REMOTE_DATA::State to SR_RS_Executing
		
		0x83, 0x7B, 0x14, 0x00,						// + 0x0E	-> cmp  dword ptr [ebx + 0x14], 0	; check if SR_REMOTE_DATA::Buffer is 0 (fake TID)
		0x74, 0x0D,									// + 0x12	-> je   0x21						; skip if no fake TID has been provided
		0x8B, 0x53, 0x14,							// + 0x14	-> mov  edx, [ebx + 0x14]			; load fake thread ID
		0x64, 0x87, 0x15, 0x24, 0x00, 0x00, 0x00,	// + 0x17	-> xchg fs:[0x24], edx				; set fake thread ID and grab real thread ID
		0x89, 0x53, 0x14,							// + 0x1E	-> mov  [ebx + 0x14], edx			; set SR_REMOTE_DATA::Buffer to the real thread ID

		0xFF, 0x73, 0x0C,							// + 0x21	-> push	[ebx + 0x0C]				; push pArg
		0xFF, 0x53, 0x10,							// + 0x24	-> call	dword ptr [ebx + 0x10]		; call pRoutine
		0x89, 0x43, 0x04,							// + 0x27	-> mov	[ebx + 0x04], eax			; store returned value

		0x64, 0xA1, 0x18, 0x00, 0x00, 0x00,			// + 0x2D	-> mov	eax, fs:[0x18]				; GetLastError
		0x8B, 0x40, 0x34,							// + 0x30	-> mov	eax, [eax + 0x34]
		0x89, 0x43, 0x08,							// + 0x33	-> mov	[ebx + 0x08], eax			; store in SR_REMOTE_DATA::LastWin32Error

		0x83, 0x7B, 0x14, 0x00,						// + 0x36	-> cmp  dword ptr [ebx + 0x14], 0	; check if SR_REMOTE_DATA::Buffer is 0 (real TID)
		0x74, 0x0A,									// + 0x3A	-> je   0x46						; skip if no TID was saved
		0x8B, 0x53, 0x14,							// + 0x3C	-> mov  edx, [ebx + 0x14]			; load real thread ID
		0x64, 0x89, 0x15, 0x24, 0x00, 0x00, 0x00,	// + 0x3F	-> mov  fs:[0x24], edx				; move real thread ID back into TEB

		0xC6, 0x03, 0x02,							// + 0x46	-> mov	byte ptr [ebx], 2			; set SR_REMOTE_DATA::State to SR_RS_ExecutionFinished
		0x31, 0xC0,									// + 0x49	-> xor	eax, eax					; zero eax (thread exitcode = 0)
		0xEB, 0x03,									// + 0x4B	-> jmp	0x50						; jump to ret

		0x83, 0xC8, 0xFF,							// + 0x4D	-> or	eax, -1						; set eax to -1 (thread exitcode = -1)

		0x5B,										// + 0x50	-> pop	ebx							; restore ebx

		0x5D,										// + 0x51	-> pop	ebp							; x86 __stdcall epilogue
		0xC2, 0x04, 0x00							// + 0x52	-> ret	0x04
	}; // SIZE = 0x55 (+ sizeof(SR_REMOTE_DATA))

#endif

	void * pMem = VirtualAllocEx(hTargetProc, nullptr, sizeof(Shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pMem)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "VirtualAllocEx failed: %08X\n", error_data.AdvErrorCode);

		return SR_NTCTE_ERR_CANT_ALLOC_MEM;
	}

	void * pRemoteFunc = ReCa<BYTE *>(pMem) + sizeof(SR_REMOTE_DATA);

	auto * sr_data = ReCa<SR_REMOTE_DATA *>(Shellcode);
	sr_data->pArg		= pArg;
	sr_data->pRoutine	= pRoutine;
	sr_data->Buffer		= FakeTID;

	LOG(2, "Codecave allocated at %p\n", pMem);

	BOOL bRet = WriteProcessMemory(hTargetProc, pMem, Shellcode, sizeof(Shellcode), nullptr);
	if (!bRet)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_NTCTE_ERR_WPM_FAIL;
	}

	LOG(2, "Creating thread with:\n");
	LOG(3, "pRoutine = %p\n", pRemoteFunc);
	LOG(3, "pArg     = %p\n", pMem);

	NTSTATUS ntRet = NATIVE::NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hTargetProc, FakeStartAddress ? pEntrypoint : pRemoteFunc, pMem, ntFlags, 0, 0, 0, nullptr);
	if (NT_FAIL(ntRet) || !hThread)
	{
		INIT_ERROR_DATA(error_data, (DWORD)ntRet);

		LOG(2, "NtCreateThreadEx failed: %08X\n", (DWORD)ntRet);

		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_NTCTE_ERR_NTCTE_FAIL;
	}

	auto TID = GetThreadId(hThread);

	LOG(2, "Thread created with TID = %06X (%06d)\n", TID, TID);

	if (FakeStartAddress)
	{
		CONTEXT ctx{ 0 };
		ctx.ContextFlags = CONTEXT_ALL;

		if (!GetThreadContext(hThread, &ctx))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(2, "GetThreadContext failed: %08X\n", error_data.AdvErrorCode);

			TerminateThread(hThread, 0);
			CloseHandle(hThread);

			VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

			return SR_NTCTE_ERR_GET_CONTEXT_FAIL;
		}

		LOG(2, "Loaded thread context\n");

#ifdef _WIN64
		ctx.Rcx = ReCa<DWORD64>(pRemoteFunc);
#else
		ctx.Eax = ReCa<DWORD>(pRemoteFunc);
#endif

		if (!SetThreadContext(hThread, &ctx))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(2, "SetThreadContext failed: %08X\n", error_data.AdvErrorCode);

			TerminateThread(hThread, 0);
			CloseHandle(hThread);

			VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

			return SR_NTCTE_ERR_SET_CONTEXT_FAIL;
		}

		LOG(2, "Thread redirected\n");
	}

	if (Flags & INJ_CTF_SKIP_THREAD_ATTACH)
	{
		THREAD_BASIC_INFORMATION tbi{ 0 };
		ntRet = NATIVE::NtQueryInformationThread(hThread, THREADINFOCLASS::ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);
		if (NT_FAIL(ntRet) || !tbi.TebBaseAddress)
		{
			INIT_ERROR_DATA(error_data, ntRet);

			LOG(2, "NtQueryInformationThread failed: %08X\n", error_data.AdvErrorCode);

			TerminateThread(hThread, 0);
			CloseHandle(hThread);

			VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

			return SR_NTCTE_ERR_NTQIT_FAIL;
		}

		WORD same_teb_flags = 0;
		if (!ReadProcessMemory(hTargetProc, ReCa<BYTE *>(tbi.TebBaseAddress) + TEB_SameTebFlags, &same_teb_flags, sizeof(same_teb_flags), nullptr))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(2, "ReadProcessMemory failed: %08X\n", error_data.AdvErrorCode);

			TerminateThread(hThread, 0);
			CloseHandle(hThread);

			VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

			return SR_NTCTE_ERR_RPM_FAIL;
		}

		same_teb_flags |= TEB_SAMETEB_FLAGS_SkipAttach;
		if (!WriteProcessMemory(hTargetProc, ReCa<BYTE *>(tbi.TebBaseAddress) + TEB_SameTebFlags, &same_teb_flags, sizeof(same_teb_flags), nullptr))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(2, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

			TerminateThread(hThread, 0);
			CloseHandle(hThread);

			VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

			return SR_NTCTE_ERR_WPM_FAIL;
		}

		LOG(2, "Fixed TEB flags\n");
	}

	if (ntFlags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED)
	{
		if (ResumeThread(hThread) == (DWORD)-1)
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(2, "ResumeThread failed: %08X\n", error_data.AdvErrorCode);

			TerminateThread(hThread, 0);
			CloseHandle(hThread);

			VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

			return SR_NTCTE_ERR_RESUME_FAIL;
		}

		LOG(2, "Thread resumed\n");
	}

	LOG(2, "Entering wait state\n");

	Sleep(SR_REMOTE_DELAY);

	DWORD dwExitCode = 0;

	SR_REMOTE_DATA data{ };
	data.State			= SR_REMOTE_STATE::SR_RS_ExecutionPending;
	data.Ret			= ERROR_SUCCESS;
	data.LastWin32Error = ERROR_SUCCESS;

	HANDLE handles[] = { hThread, g_hInterruptedEvent };

	DWORD dwWaitRet = WaitForMultipleObjects(2, handles, FALSE, Timeout);
	if (dwWaitRet != WAIT_OBJECT_0)
	{
		if (dwWaitRet == (WAIT_OBJECT_0 + 1))
		{
			INIT_ERROR_DATA(error_data, dwWaitRet);

			LOG(2, "Interrupt!\n");
		}
		else
		{
			if (dwWaitRet == WAIT_FAILED)
			{
				INIT_ERROR_DATA(error_data, GetLastError());
			}
			else
			{
				INIT_ERROR_DATA(error_data, dwWaitRet);
			}

			LOG(2, "WaitForSingleObject failed: %08X\n", error_data.AdvErrorCode);
		}

		TerminateThread(hThread, 0);
		CloseHandle(hThread);

		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		if (dwWaitRet == (WAIT_OBJECT_0 + 1))
		{
			SetEvent(g_hInterruptedEvent);

			return SR_ERR_INTERRUPT;
		}

		return SR_NTCTE_ERR_REMOTE_TIMEOUT;
	}

	LOG(2, "Thread finished execution\n");

	if (!GetExitCodeThread(hThread, &dwExitCode))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "GetExitCodeThread failed: %08X\n", error_data.AdvErrorCode);

		CloseHandle(hThread);

		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_NTCTE_ERR_GECT_FAIL;
	}

	bRet = ReadProcessMemory(hTargetProc, pMem, &data, sizeof(data), nullptr);
	
	DWORD dwErr = GetLastError();

	CloseHandle(hThread);

	VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

	if (bRet)
	{
		LOG(2, "Thread exit data retrieved\n");

		if (data.State != SR_REMOTE_STATE::SR_RS_ExecutionFinished)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(2, "Shell timed out\n");

			return SR_NTCTE_ERR_REMOTE_TIMEOUT;
		}
	}

	if (dwExitCode == 0xFFFFFFFF)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "Shellcode creation failed\n");

		return SR_NTCTE_ERR_SHELLCODE_SETUP_FAIL;
	}
	else if (!bRet)
	{
		INIT_ERROR_DATA(error_data, dwErr);

		LOG(2, "ReadProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		return SR_NTCTE_ERR_RPM_FAIL;
	}

	LOG(2, "pRoutine returned: %08X\n", data.Ret);

	Out	= data.Ret;
			
	return SR_ERR_SUCCESS;
}