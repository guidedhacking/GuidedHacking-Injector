#include "pch.h"

#ifdef _WIN64

#include "Start Routine.h"

DWORD SR_NtCreateThreadEx_WOW64(HANDLE hTargetProc, f_Routine_WOW64 pRoutine, DWORD pArg, bool CloakThread, DWORD & Out, DWORD Timeout, ERROR_DATA & error_data)
{
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

	DWORD Flags		= THREAD_CREATE_FLAGS_CREATE_SUSPENDED | THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
	HANDLE hThread	= nullptr;

	void * pMem = VirtualAllocEx(hTargetProc, nullptr, 0x200, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!pMem)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		return SR_NTCTE_ERR_CANT_ALLOC_MEM;
	}

	BYTE Shellcode[] =
	{
		SR_REMOTE_DATA_BUFFER_86

		0x55,								// + 0x00	-> push   ebp					; x86 stack frame creation
		0x89, 0xE5,							// + 0x01	-> mov    ebp, esp

		0x53,								// + 0x03	-> push   ebx					; push ebx on stack (non volatile)
		0x8B, 0x5D, 0x08,					// + 0x04	-> mov    ebx, [ebp + 0x08]		; store pData in ebx
		0x85, 0xDB,							// + 0x07	-> test   ebx, ebx				; check if pData is valid
		0x74, 0x23,							// + 0x09	-> je     0x2E					; jmp to ret if not and set eax to -1

		0xC6, 0x03, 0x01,					// + 0x0B	-> mov    BYTE PTR [ebx], 1		; set SR_REMOTE_DATA::State to SR_RS_Executing

		0xFF, 0x73, 0x0C,					// + 0x0E	-> push   [ebx + 0x0C]			; push pArg
		0xFF, 0x53, 0x10,					// + 0x11	-> call   [ebx + 0x10]			; call pRoutine
		0x89, 0x43, 0x04,					// + 0x14	-> mov    [ebx + 0x04], eax		; store returned value

		0x85, 0xC0,							// + 0x17	-> test   eax, eax				; check if eax is 0 (SUCCESS)
		0x74, 0x0C,							// + 0x19	-> je     0x27					; jmp if equal/zero

		0x64, 0xA1, 0x18, 0x00, 0x00, 0x00,	// + 0x1B	-> mov    eax, fs:[0x18]		; GetLastError
		0x8B, 0x40, 0x34,					// + 0x21	-> mov    eax, [eax + 0x34]
		0x89, 0x43, 0x08,					// + 0x24	-> mov    [ebx + 0x08], eax		; store in SR_REMOTE_DATA::LastWin32Error

		0xC6, 0x03, 0x02,					// + 0x27	-> mov    BYTE PTR [ebx], 2		; set SR_REMOTE_DATA::State to SR_RS_ExecutionFinished
		0x31, 0xC0,							// + 0x2A	-> xor    eax, eax				; zero eax (thread exitcode = 0)
		0xEB, 0x03,							// + 0x2C	-> jmp    0x31					; jump to ret

		0x83, 0xC8, 0xFF,					// + 0x2E	-> or     eax, -1				; set eax to -1 (thread exitcode = -1)

		0x5B,								// + 0x31	-> pop    ebx					; restore ebx
		0x5D,								// + 0x32	-> pop    ebp					; store ebp
		0xC2, 0x04, 0x00					// + 0x33	-> ret    0x04					; return
	}; // SIZE = 0x36 (+ sizeof(SR_REMOTE_DATA))

	void * pRemoteFunc = ReCa<BYTE*>(pMem) + sizeof(SR_REMOTE_DATA_WOW64);

	auto * sr_data = ReCa<SR_REMOTE_DATA_WOW64*>(Shellcode);
	sr_data->pArg		= MDWD(pArg);
	sr_data->pRoutine	= MDWD(pRoutine);

	BOOL bRet = WriteProcessMemory(hTargetProc, pMem, Shellcode, sizeof(Shellcode), nullptr);
	if (!bRet)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_NTCTE_ERR_WPM_FAIL;
	}

	NTSTATUS ntRet = NATIVE::NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hTargetProc, CloakThread ? pEntrypoint : pRemoteFunc, pMem, CloakThread ? Flags : NULL, 0, 0, 0, nullptr);
	if (NT_FAIL(ntRet) || !hThread)
	{
		INIT_ERROR_DATA(error_data, (DWORD)ntRet);

		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_NTCTE_ERR_NTCTE_FAIL;
	}

	if (CloakThread)
	{
		WOW64_CONTEXT ctx{ 0 };
		ctx.ContextFlags = WOW64_CONTEXT_ALL;

		if (!Wow64GetThreadContext(hThread, &ctx))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			TerminateThread(hThread, 0);
			CloseHandle(hThread);

			VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

			return SR_NTCTE_ERR_GET_CONTEXT_FAIL;
		}

		ctx.Eax = MDWD(pRemoteFunc);

		if (!Wow64SetThreadContext(hThread, &ctx))
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

	DWORD dwWaitRet = WaitForSingleObject(hThread, Timeout);
	if (dwWaitRet != WAIT_OBJECT_0)
	{
		INIT_ERROR_DATA(error_data, dwWaitRet);

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

	SR_REMOTE_DATA_WOW64 data;
	bRet = ReadProcessMemory(hTargetProc, pMem, &data, sizeof(data), nullptr);
	DWORD dwErr = GetLastError();

	VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);
	
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

	Out = data.Ret;

	return SR_ERR_SUCCESS;
}

#endif