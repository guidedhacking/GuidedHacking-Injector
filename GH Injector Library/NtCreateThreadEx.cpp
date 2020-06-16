#include "pch.h"

#include "Start Routine.h"

DWORD SR_NtCreateThreadEx(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, bool CloakThread, DWORD & Out, ERROR_DATA & error_data)
{
	LOG("Begin SR_NtCreateThreadEx\n");

	void * pEntrypoint = nullptr;
	if (CloakThread)
	{
		ProcessInfo pi;
		if (!pi.SetProcess(hTargetProc))
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			return SR_NTCTE_ERR_PROC_INFO_FAIL;
		}

		pEntrypoint = pi.GetEntrypoint();
	}
	DWORD Flags		= THREAD_CREATE_FLAGS_CREATE_SUSPENDED | THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH | THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
	HANDLE hThread	= nullptr;

#ifdef _WIN64

	BYTE Shellcode[] =
	{
		SR_REMOTE_DATA_BUFFER_64

	    0x48, 0x85, 0xC9,										// + 0x00	-> test	rcx, rcx				; check if pData is valid
		0x74, 0x3D,												// + 0x03	-> je	0x42					; jmp to ret if not and set rax to -1

		0x53,													// + 0x05	-> push rbx						; push rbx on stack (non volatile)
		0x48, 0x8B, 0xD9,										// + 0x06	-> mov	rbx, rcx				; store pArg in rbx
		0xC7, 0x03, 0x01, 0x00, 0x00, 0x00,						// + 0x09	-> mov	[rbx], 1				; set SR_REMOTE_DATA::State to SR_RS_Executing

		0x48, 0x8B, 0x4B, 0x18,									// + 0x0F	-> mov  rcx, [rbx + 0x18]		; move pArg into rcx
		0x48, 0x83, 0xEC, 0x20,									// + 0x13	-> sub	rsp, 0x20				; reserve stack
		0xFF, 0x53, 0x20,										// + 0x17	-> call qword ptr [rbx + 0x20]	; call pRoutine
		0x48, 0x83, 0xC4, 0x20,									// + 0x1A	-> add	rsp, 0x20				; update stack
		0x48, 0x89, 0x43, 0x08,									// + 0x1E	-> mov	[rbx + 0x08], rax		; store returned value
		
		0x48, 0x85, 0xC0,										// + 0x22	-> test rax, rax				; check if rax is 0 (SUCCESS)
		0x74, 0x0F,												// + 0x25	-> je	0x36					; jmp if equal/zero

		0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,	// + 0x27	-> mov	rax, gs:[0x30]			; GetLastError
		0x8B, 0x40, 0x68,										// + 0x30	-> mov	eax, [rax + 0x68]
		0x89, 0x43, 0x10,										// + 0x33	-> mov	[rbx + 0x10], eax		; store in SR_REMOTE_DATA::LastWin32Error

		0xC7, 0x03, 0x02, 0x00, 0x00, 0x00,						// + 0x36	-> mov	[rbx], 2				; set SR_REMOTE_DATA::State to SR_RS_ExecutionFinished
		0x5B,													// + 0x3C	-> pop	rbx						; restore rbx

		0x48, 0x31, 0xC0,										// + 0x3D	-> xor	rax, rax				; zero rax (thread exitcode = 0)
		0xEB, 0x04,												// + 0x40	-> jmp	0x46					; jmp to ret
		
		0x48, 0x83, 0xC8, 0xFF,									// + 0x42	-> or rax, -1					; set rax to -1 (thread exitcode = -1)

		0xC3													// + 0x46	-> ret							; return
	}; // SIZE = 0x47 (+ sizeof(SR_REMOTE_DATA))
		
#else

	BYTE Shellcode[] =
	{
		SR_REMOTE_DATA_BUFFER_86

		0x55,								// + 0x00	-> push	ebp						; x86 stack frame creation
		0x89, 0xE5,							// + 0x01	-> mov	ebp, esp

		0x53,								// + 0x03	-> push	ebx						; push ebx on stack (non volatile)
		0x8B, 0x5D, 0x08,					// + 0x04	-> mov	ebx, [ebp + 0x08]		; store pData in ebx
		0x85, 0xDB,							// + 0x07	-> test	ebx, ebx				; check if pData is valid
		0x74, 0x23,							// + 0x09	-> je	0x2E					; jmp to ret if not and set eax to -1

		0xC6, 0x03, 0x01,					// + 0x0B	-> mov	byte ptr [ebx], 1		; set SR_REMOTE_DATA::State to SR_RS_Executing

		0xFF, 0x73, 0x0C,					// + 0x0E	-> push	[ebx + 0x0C]			; push pArg
		0xFF, 0x53, 0x10,					// + 0x11	-> call	dword ptr [ebx + 0x10]	; call pRoutine
		0x89, 0x43, 0x04,					// + 0x14	-> mov	[ebx + 0x04], eax		; store returned value

		0x85, 0xC0,							// + 0x17	-> test	eax, eax				; check if eax is 0 (SUCCESS)
		0x74, 0x0C,							// + 0x19	-> je	0x27					; jmp if equal/zero

		0x64, 0xA1, 0x18, 0x00, 0x00, 0x00,	// + 0x1B	-> mov	eax, fs:[0x18]			; GetLastError
		0x8B, 0x40, 0x34,					// + 0x21	-> mov	eax, [eax + 0x34]
		0x89, 0x43, 0x08,					// + 0x24	-> mov	[ebx + 0x08], eax		; store in SR_REMOTE_DATA::LastWin32Error

		0xC6, 0x03, 0x02,					// + 0x27	-> mov	byte ptr [ebx], 2		; set SR_REMOTE_DATA::State to SR_RS_ExecutionFinished
		0x31, 0xC0,							// + 0x2A	-> xor	eax, eax				; zero eax (thread exitcode = 0)
		0xEB, 0x03,							// + 0x2C	-> jmp	0x31					; jump to ret

		0x83, 0xC8, 0xFF,					// + 0x2E	-> or	eax, -1					; set eax to -1 (thread exitcode = -1)

		0x5B,								// + 0x31	-> pop	ebx						; restore ebx
		0x5D,								// + 0x32	-> pop	ebp						; restore ebp
		0xC2, 0x04, 0x00					// + 0x33	-> ret	0x04					; return
	}; // SIZE = 0x36 (+ sizeof(SR_REMOTE_DATA))

#endif

	LOG("Created codecave\n");

	void * pMem = VirtualAllocEx(hTargetProc, nullptr, sizeof(Shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pMem)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		return SR_NTCTE_ERR_CANT_ALLOC_MEM;
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

		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_NTCTE_ERR_WPM_FAIL;
	}
	
	LOG("Creating thread with\npRoutine = %p\npArg = %p\n", pRemoteFunc, pMem);

	NTSTATUS ntRet = NATIVE::NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hTargetProc, CloakThread ? pEntrypoint : pRemoteFunc, pMem, CloakThread ? Flags : NULL, 0, 0, 0, nullptr);
	if (NT_FAIL(ntRet) || !hThread)
	{
		INIT_ERROR_DATA(error_data, (DWORD)ntRet);

		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_NTCTE_ERR_NTCTE_FAIL;
	}

	auto TID = GetThreadId(hThread);
	LOG("Thread created with TID = %06X (%06d)\n", TID, TID);
	
	if (CloakThread)
	{
		CONTEXT ctx{ 0 };
		ctx.ContextFlags = CONTEXT_INTEGER;

		if (!GetThreadContext(hThread, &ctx))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			TerminateThread(hThread, 0);
			CloseHandle(hThread);

			VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

			return SR_NTCTE_ERR_GET_CONTEXT_FAIL;
		}

#ifdef _WIN64
		ctx.Rcx = ReCa<DWORD64>(pRemoteFunc);
#else
		ctx.Eax = ReCa<DWORD>(pRemoteFunc);
#endif

		if (!SetThreadContext(hThread, &ctx))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			TerminateThread(hThread, 0);
			CloseHandle(hThread);

			VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

			return SR_NTCTE_ERR_SET_CONTEXT_FAIL;
		}

		if (ResumeThread(hThread) == (DWORD)-1)
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			TerminateThread(hThread, 0);
			CloseHandle(hThread);

			VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

			return SR_NTCTE_ERR_RESUME_FAIL;
		}
	}

	LOG("Entering wait state\n");

	Sleep(100);
	
	DWORD dwWaitRet = WaitForSingleObject(hThread, SR_REMOTE_TIMEOUT);
	if (dwWaitRet != WAIT_OBJECT_0)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		TerminateThread(hThread, 0);
		CloseHandle(hThread);

		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_NTCTE_ERR_REMOTE_TIMEOUT;
	}

	DWORD dwExitCode = 0;
	if (!GetExitCodeThread(hThread, &dwExitCode))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		CloseHandle(hThread);

		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_NTCTE_ERR_GECT_FAIL;
	}

	CloseHandle(hThread);

	SR_REMOTE_DATA data;
	bRet = ReadProcessMemory(hTargetProc, pMem, &data, sizeof(data), nullptr);
	DWORD dwErr = GetLastError();

	VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

	LOG("Thread exit data retrieved\n");

	if (dwExitCode == 0xFFFFFFFF)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return SR_NTCTE_ERR_SHELLCODE_SETUP_FAIL;
	}
	else if (!bRet)
	{
		INIT_ERROR_DATA(error_data, dwErr);

		return SR_NTCTE_ERR_RPM_FAIL;
	}

	Out	= data.Ret;

	LOG("End SR_NtCreateThreadEx\n");
			
	return SR_ERR_SUCCESS;
}