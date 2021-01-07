#include "pch.h"

#include "Start Routine.h"

DWORD SR_SetWindowsHookEx(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, ULONG TargetSessionId, DWORD & Out, DWORD Timeout, ERROR_DATA & error_data)
{
	LOG("Begin SR_SetWindowsHookEx\n");

	std::wstring InfoPath = g_RootPathW;
	InfoPath += SM_INFO_FILENAME;
		
	if (FileExists(InfoPath.c_str()))
	{
		DeleteFileW(InfoPath.c_str());
	}

	std::wofstream swhex_info(InfoPath, std::ios_base::out | std::ios_base::app);
	if (!swhex_info.good())
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG("Failed to create info file\n");

		return SR_SWHEX_ERR_CANT_OPEN_INFO_TXT;
	}

	void * pMem = VirtualAllocEx(hTargetProc, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pMem)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG("VirtualAllocEx failed: %08X\n", error_data.AdvErrorCode);

		swhex_info.close();
		DeleteFileW(InfoPath.c_str());

		return SR_SWHEX_ERR_CANT_ALLOC_MEM;
	}

	LOG("Codecave allocated at %p\n", pMem);
	
#ifdef _WIN64

	BYTE Shellcode[] =
	{
		SR_REMOTE_DATA_BUFFER_64

		0x53,													// + 0x00	-> push rbx						; push rbx on stack (non volatile)
		0x48, 0x8D, 0x1D, 0xC8, 0xFF, 0xFF, 0xFF,				// + 0x01	-> lea rbx, [-0x30]				; load pData into rbx

		0x83, 0x3B, 0x00,										// + 0x08	-> cmp	dword ptr [rbx], 0x00	; test if SR_REMOTE_DATA::State is equal to SR_RS_ExecutionPending
		0x75, 0x33,												// + 0x0B	-> jne	0x41					; jump if not equal

		0xC7, 0x03, 0x01, 0x00, 0x00, 0x00,						// + 0x0D	-> mov	[rbx], 1				; set SR_REMOTE_DATA::State to SR_RS_Executing

		0x48, 0x8B, 0x4B, 0x18,									// + 0x13	-> mov  rcx, [rbx + 0x18]		; move pArg into rcx
		0x48, 0x83, 0xEC, 0x20,									// + 0x17	-> sub	rsp, 0x20				; reserve stack
		0xFF, 0x53, 0x20,										// + 0x1B	-> call qword ptr [rbx + 0x20]	; call pRoutine
		0x48, 0x83, 0xC4, 0x20,									// + 0x1E	-> add	rsp, 0x20				; update stack
		0x48, 0x89, 0x43, 0x08,									// + 0x22	-> mov	[rbx + 0x08], rax		; store returned value

		0x48, 0x85, 0xC0,										// + 0x26	-> test rax, rax				; check if rax is 0 (SUCCESS)
		0x74, 0x0F,												// + 0x29	-> je	0x3B					; jmp if equal/zero

		0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,	// + 0x2B	-> mov	rax, gs:[0x30]			; GetLastError
		0x8B, 0x40, 0x68,										// + 0x34	-> mov	eax, [rax + 0x68]
		0x89, 0x43, 0x10,										// + 0x37	-> mov	[rbx + 0x10], eax		; store in SR_REMOTE_DATA::LastWin32Error

		0xC7, 0x03, 0x02, 0x00, 0x00, 0x00,						// + 0x3A	-> mov	[rbx], 2				; set SR_REMOTE_DATA::State to SR_RS_ExecutionFinished

		0x5B,													// + 0x40	-> pop	rbx						; restore rbx

		0x48, 0x31, 0xC0,										// + 0x41	-> xor	rax, rax				; set rax to 0 to prevent further handling of the message

		0xC3													// + 0x44	-> ret							; return
	}; // SIZE = 0x45 (+ sizeof(SR_REMOTE_DATA))
	
#else

	BYTE Shellcode[] =
	{
		SR_REMOTE_DATA_BUFFER_86

		0x53,								// + 0x00			-> push	ebx						; push ebx on stack (non volatile)
		0xBB, 0x00, 0x00, 0x00, 0x00,		// + 0x01 (+ 0x02)	-> mov	ebx, 0x00000000			; move pData into ebx (update address manually on runtime)
		0x83, 0x3B, 0x00,					// + 0x06			-> cmp	dword ptr [ebx], 0x00	; test if SR_REMOTE_DATA::State is equal to SR_RS_ExecutionPending
		0x75, 0x1F,							// + 0x09			-> jne	0x2A					; jump if not equal

		0xC6, 0x03, 0x01,					// + 0x0B			-> mov	byte ptr [ebx], 1		; set SR_REMOTE_DATA::State to SR_RS_Executing

		0xFF, 0x73, 0x0C,					// + 0x0E			-> push	[ebx + 0x0C]			; push pArg
		0xFF, 0x53, 0x10,					// + 0x11			-> call dword ptr [ebx + 0x10]	; call pRoutine
		0x89, 0x43, 0x04,					// + 0x14			-> mov	[ebx + 0x04], eax		; store returned value
		
		0x85, 0xC0,							// + 0x17			-> test eax, eax				; check if eax is 0 (SUCCESS)
		0x74, 0x0C,							// + 0x19			-> je	0x27					; jmp if equal/zero
		
		0x64, 0xA1, 0x18, 0x00, 0x00, 0x00,	// + 0x1B			-> mov	eax, fs:[0x18]			; GetLastError
		0x8B, 0x40, 0x34,					// + 0x21			-> mov	eax, [eax + 0x34]
		0x89, 0x43, 0x08,					// + 0x24			-> mov	[ebx + 0x08], eax		; store in SR_REMOTE_DATA::LastWin32Error

		0xC6, 0x03, 0x02,					// + 0x27			-> mov	byte ptr [ebx], 2		; set SR_REMOTE_DATA::State to SR_RS_ExecutionFinished

		0x5B,								// + 0x2A			-> pop	ebx						; restore ebx
		0x31, 0xC0,							// + 0x2B			-> xor	eax, eax				; set eax to 0 to prevent further handling of the message
		0xC2, 0x04, 0x00					// + 0x2D			-> ret	0x04					; return
	}; // SIZE = 0x30 (+ sizeof(SR_REMOTE_DATA))

	*ReCa<void**>(Shellcode + 0x02 + sizeof(SR_REMOTE_DATA)) = pMem;

#endif
	
	void * pRemoteFunc = ReCa<BYTE*>(pMem) + sizeof(SR_REMOTE_DATA);

	auto * sr_data = ReCa<SR_REMOTE_DATA*>(Shellcode);
	sr_data->pArg		= pArg;
	sr_data->pRoutine	= pRoutine;

	if (!WriteProcessMemory(hTargetProc, pMem, Shellcode, sizeof(Shellcode), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG("WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		swhex_info.close();
		DeleteFileW(InfoPath.c_str());

		return SR_SWHEX_ERR_WPM_FAIL;
	}

	LOG("Hooks called with\n pRoutine = %p\n pArg = %p\n", pRemoteFunc, pMem);

	swhex_info << std::dec << GetProcessId(hTargetProc) << '!' << std::hex << ReCa<ULONG_PTR>(pRemoteFunc) << std::endl;
	swhex_info.close();

	std::wstring smPath = g_RootPathW;
	smPath += SM_EXE_FILENAME;

	wchar_t cmdLine[] = L"\"" SM_EXE_FILENAME "\" 0";

	PROCESS_INFORMATION pi{ 0 };
	STARTUPINFOW		si{ 0 };
	si.cb			= sizeof(si);
	si.dwFlags		= STARTF_USESHOWWINDOW;
	si.wShowWindow	= SW_HIDE;

	LOG("Data and command line prepared\n");

	if (TargetSessionId != -1)
	{
		LOG("Target process is in a different session\n");

		HANDLE hUserToken = nullptr;
		if (!WTSQueryUserToken(TargetSessionId, &hUserToken))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG("WTSQueryUserToken failed: %08X\n", error_data.AdvErrorCode);

			VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);
			DeleteFileW(InfoPath.c_str());

			return SR_SWHEX_ERR_WTSQUERY_FAIL;
		}

		HANDLE hNewToken = nullptr;
		if (!DuplicateTokenEx(hUserToken, MAXIMUM_ALLOWED, nullptr, SecurityIdentification, TokenPrimary, &hNewToken))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG("DuplicateTokenEx failed: %08X\n", error_data.AdvErrorCode);

			CloseHandle(hUserToken);
			VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);
			DeleteFileW(InfoPath.c_str());

			return SR_SWHEX_ERR_DUP_TOKEN_FAIL;
		}

		DWORD SizeOut = 0;
		TOKEN_LINKED_TOKEN admin_token{ 0 };
		if (!GetTokenInformation(hNewToken, TokenLinkedToken, &admin_token, sizeof(admin_token), &SizeOut))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG("GetTokenInformation failed: %08X\n", error_data.AdvErrorCode);

			CloseHandle(hNewToken);
			CloseHandle(hUserToken);
			VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);
			DeleteFileW(InfoPath.c_str());

			return SR_SWHEX_ERR_GET_ADMIN_TOKEN_FAIL;
		}

		HANDLE hAdminToken = admin_token.LinkedToken;

		LOG("Token prepared\n");

		LOG("Launching %ls:\n %ls\n", SM_EXE_FILENAME, cmdLine);

		if (!CreateProcessAsUserW(hAdminToken, smPath.c_str(), cmdLine, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG("CreateProcessAsUserW failed: %08X\n", error_data.AdvErrorCode);

			CloseHandle(hAdminToken);
			CloseHandle(hNewToken);
			CloseHandle(hUserToken);
			VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);
			DeleteFileW(InfoPath.c_str());

			return SR_SWHEX_ERR_CANT_CREATE_PROCESS;
		}

		LOG("%ls launched\n", SM_EXE_FILENAME);

		CloseHandle(hAdminToken);
		CloseHandle(hNewToken);
		CloseHandle(hUserToken);
	}
	else
	{
		LOG("Launching %ls:\n %ls\n", SM_EXE_FILENAME, cmdLine);

		if (!CreateProcessW(smPath.c_str(), cmdLine, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG("CreateProcessW failed: %08X\n", error_data.AdvErrorCode);

			VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);
			DeleteFileW(InfoPath.c_str());

			return SR_SWHEX_ERR_CANT_CREATE_PROCESS;
		}

		LOG("%ls launched\n", SM_EXE_FILENAME);
	}

	LOG("Entering wait state\n");

	Sleep(SR_REMOTE_DELAY);

	auto Timer = GetTickCount64();

	DWORD dwWaitRet = WaitForSingleObject(pi.hProcess, Timeout);
	if (dwWaitRet != WAIT_OBJECT_0)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG("%ls timed out: %08X\n", SM_EXE_FILENAME, error_data.AdvErrorCode);

		TerminateProcess(pi.hProcess, 0);
		DeleteFileW(InfoPath.c_str());

		return SR_SWHEX_ERR_SWHEX_TIMEOUT;
	}

	DWORD ExitCode = 0;
	GetExitCodeProcess(pi.hProcess, &ExitCode);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	DeleteFileW(InfoPath.c_str());

	if (ExitCode != SWHEX_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, ExitCode);

		LOG("%ls failed: %08X\n", SM_EXE_FILENAME, ExitCode);

		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return ExitCode;
	}
	
	SR_REMOTE_DATA data;
	data.State			= SR_REMOTE_STATE::SR_RS_ExecutionPending;
	data.Ret			= ERROR_SUCCESS;
	data.LastWin32Error = ERROR_SUCCESS;

	while (GetTickCount64() - Timer < Timeout)
	{
		BOOL bRet = ReadProcessMemory(hTargetProc, pMem, &data, sizeof(data), nullptr);
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

			VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

			return SR_SWHEX_ERR_RPM_FAIL;
		}

		Sleep(10);
	}

	VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

	if (data.State != SR_REMOTE_STATE::SR_RS_ExecutionFinished)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG("Shell timed out\n");

		return SR_SWHEX_ERR_REMOTE_TIMEOUT;
	}

	LOG("pRoutine returned: %08X\n", data.Ret);

	Out = data.Ret;

	LOG("End SR_SetWindowsHookEx\n");

	return SR_ERR_SUCCESS;
}