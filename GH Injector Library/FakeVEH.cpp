#include "pch.h"

#include "Start Routine.h"

DWORD SR_FakeVEH(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD & Out, DWORD Timeout, ERROR_DATA & error_data)
{
	LOG(2, "Begin SR_FakeVEH\n");

	void * pMem = VirtualAllocEx(hTargetProc, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pMem)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "VirtualAllocEx failed: %08X\n", error_data.AdvErrorCode);

		return SR_VEH_ERR_CANT_ALLOC_MEM;
	}

	/*
		LONG __stdcall VectoredExceptionHandler_Shell(EXCEPTION_POINTERS * ExceptionInfo)
		{
			if (ExceptionInfo != nullptr)
			{
				if (ExceptionInfo->ExceptionRecord != nullptr)
				{
					if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_GUARD_PAGE)
					{
						SR_REMOTE_DATA_VEH * data = ReCa<SR_REMOTE_DATA_VEH *>(ReCa<BYTE *>(VectoredExceptionHandler) - sizeof(SR_REMOTE_DATA_VEH));
						if (data->Data.State == SR_REMOTE_STATE::SR_RS_ExecutionPending)
						{
							if (data->pLdrProtectMrdata) //only Win8.1+
							{
								data->pLdrProtectMrdata(FALSE); //return value is irrelevant
							}

							LIST_ENTRY * current = data->pListHead.Flink; //find fake entry in LdrpVectoredHandlerList
							while (current != data->pListHead)
							{
								if (current == data->pFakeEntry) //found entry
								{
									current->Blink->Flink = current->Flink; //unlink it
									current->Flink->Blink = current->Blink;

									break;
								}

								current = current->Flink;
							} //can't do anything if not found in this list

							if (data->pLdrProtectMrdata)
							{
								data->pLdrProtectMrdata(TRUE); //restore protection state
							}

							data->Data.State = SR_REMOTE_STATE::SR_RS_Executing;

							data->Data.Ret = data->pRoutine(data->pArg);
							data->Data.LastWin32Error = GetLastError(); //inlined

							data->Data.State = SR_REMOTE_STATE::SR_RS_ExecutionFinished;

							return EXCEPTION_CONTINUE_EXECUTION;
						}
					}
				}
			}

			return EXCEPTION_CONTINUE_SEARCH;
		}
	*/

	#ifdef _WIN64

	BYTE Shellcode[] =
	{
		SR_REMOVE_DATA_BUFFER_VEH

		0x48, 0x85, 0xC9,										// + 0x00	-> test rcx, rcx					; check if rcx (ExceptionInfo pointer) is non-zero
		0x0F, 0x84, 0x9D, 0x00, 0x00, 0x00,						// + 0x03	-> je	0xA6						; jump if nullptr

		0x48, 0x8B, 0x09,										// + 0x09	-> mov	rcx, [rcx]					; move EXCEPTION_POINTERS::ExceptionRecord into rcx
		0x48, 0x85, 0xC9,										// + 0x0C	-> test rcx, rcx					; check if ExceptionRecord is non-zero
		0x0F, 0x84, 0x91, 0x00, 0x00, 0x00,						// + 0x0F	-> je	0xA6						; jump if nullptr

		0x81, 0x39, 0x01, 0x00, 0x00, 0x80,						// + 0x15	-> cmp	dword ptr [rcx], 0x80000001	; check if ExceptionRecord::ExceptionCode matches EXCEPTION_GUARD_PAGE
		0x0F, 0x85, 0x85, 0x00, 0x00, 0x00,						// + 0x1B	-> jne	0xA6						; jump if not equal

		0x53,													// + 0x21	-> push rbx							; push rbx on stack (non volatile)
		0x48, 0x8D, 0x1D, 0x8F, 0xFF, 0xFF, 0xFF,				// + 0x22	-> lea	rbx, [-0x48]				; load pData into rbx

		0x80, 0x3B, 0x00,										// + 0x29	-> cmp	byte ptr [rbx], 0			; test if SR_REMOTE_DATA::State is equal to SR_RS_ExecutionPending
		0x75, 0x77,												// + 0x2C	-> jne	0xA5						; jump if not equal

		0xC6, 0x03, 0x01,										// + 0x2E	-> mov	byte ptr [rbx], 1			; set SR_REMOTE_DATA::State to SR_RS_Executing

		0x48, 0x83, 0x7B, 0x30, 0x00,							// + 0x31	-> cmp  qword ptr [rbx + 0x30], 0	; check if SR_REMOTE_DATA_VEH::pLdrProtectMrdata is non-zero
		0x74, 0x0A,												// + 0x36	-> je   0x42						; jump if nullptr
		0x48, 0x31, 0xC9,										// + 0x38	-> xor  rcx, rcx					; move FALSE into rcx
		0x48, 0x83, 0xEC, 0x20,									// + 0x3B	-> sub  rsp, 0x20					; reserve 0x20 bytes on the stack
		0xFF, 0x53, 0x30,										// + 0x3F	-> call qword ptr [rbx + 0x30]		; call LdrProtectMrdata to make LdrpVectorHandlerList writeable

		0x48, 0x8B, 0x53, 0x38,									// + 0x42	-> mov  rdx, [rbx + 0x38]			; move &LdrpVectorHandlerList.List (head) into rdx
		0x48, 0x8B, 0x0A,										// + 0x46	-> mov  rcx, [rdx]					; move head->Flink into rcx (current)

		0x48, 0x39, 0xD1,										// + 0x49	-> cmp  rcx, rdx					; compare current, head
		0x74, 0x19,												// + 0x4C	-> je   0x67						; exit loop if equal (end of list)
		0x48, 0x3B, 0x4B, 0x40,									// + 0x4E	-> cmp  rcx, [rbx + 0x40]			; compare current, SR_REMOTE_DATA_VEH::pFakeEntry
		0x74, 0x05,												// + 0x52	-> je   0x59						; break loop if equal (found entry)
		0x48, 0x8B, 0x09,										// + 0x54	-> mov  rcx, [rcx]					; set current to current->Flink
		0xEB, 0xF0,												// + 0x57	-> jmp  0x49						; jmp to the start of the loop

		0x48, 0x8B, 0x01,										// + 0x59	-> mov  rax, [rcx]					; store current->Flink in rax
		0x48, 0x8B, 0x51, 0x08,									// + 0x5C	-> mov  rdx, [rcx + 0x08]			; store current->Blink in rdx
		0x48, 0x89, 0x02,										// + 0x60	-> mov  [rdx], rax					; current->Blink->Flink = current->Fink
		0x48, 0x89, 0x50, 0x08,									// + 0x63	-> mov  [rax + 0x08], rdx			; current->Flink->Blink = current->Blink

		0x48, 0x83, 0x7B, 0x30, 0x00,							// + 0x67	-> cmp  qword ptr [rbx + 0x30], 0	; check if SR_REMOTE_DATA_VEH::pLdrProtectMrdata is non-zero
		0x74, 0x0C,												// + 0x6C	-> je   0x7A						; jump if nullptr
		0x48, 0x31, 0xC9,										// + 0x6E	-> xor  rcx, rcx					; zero rcx
		0xB1, 0x01,												// + 0x71	-> mov  cl, 1						; move TRUE into rcx
		0xFF, 0x53, 0x30,										// + 0x73	-> call qword ptr [rbx + 0x30]		; call LdrProtectMrdata to protect LdrpVectorHandlerList
		0x48, 0x83, 0xC4, 0x20,									// + 0x76	-> add  rsp, 0x20					; restore stack (reserved at + 0x3B)

		0x48, 0x8B, 0x4B, 0x18,									// + 0x7A	-> mov	rcx, [rbx + 0x18]			; move pArg into rcx
		0x48, 0x83, 0xEC, 0x20,									// + 0x7E	-> sub	rsp, 0x20					; reserve stack
		0xFF, 0x53, 0x20,										// + 0x82	-> call qword ptr [rbx + 0x20]		; call pRoutine
		0x48, 0x83, 0xC4, 0x20,									// + 0x85	-> add	rsp, 0x20					; update stack
		0x48, 0x89, 0x43, 0x08,									// + 0x89	-> mov	[rbx + 0x08], rax			; store returned value

		0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,	// + 0x8D	-> mov	rax, gs: [0x30]				; GetLastError
		0x8B, 0x40, 0x68,										// + 0x89	-> mov	eax, [rax + 0x68]
		0x89, 0x43, 0x10,										// + 0x99	-> mov	[rbx + 0x10], eax			; store in SR_REMOTE_DATA::LastWin32Error

		0xC6, 0x03, 0x02,										// + 0x9C	-> mov	byte ptr [rbx], 2			; set SR_REMOTE_DATA::State to SR_RS_ExecutionFinished

		0x83, 0xC8, 0xFF,										// + 0x9F	-> or	eax, -1						; set eax to EXCEPTION_CONTINUE_EXECUTION
		0x5B,													// + 0xA2	-> pop	rbx							; restore rbx
		0xEB, 0x04,												// + 0xA3	-> jmp	0xA9						; jump to ret

		0x5B,													// + 0xA5	-> pop	rbx							; restore rbx			
		0x48, 0x31, 0xC0,										// + 0xA6	-> xor	rax, rax					; set eax to EXCEPTION_CONTINUE_SEARCH

		0xC3													// + 0xA9	-> ret								; return

	}; // SIZE = 0x9A (+ sizeof(SR_REMOTE_DATA_VEH))
	
#else

	BYTE Shellcode[] =
	{
		SR_REMOVE_DATA_BUFFER_VEH

		0x55,								// + 0x00			-> push ebp							; x86 stack frame creation
		0x8B, 0xEC,							// + 0x01			-> mov  ebp, esp

		0x8B, 0x4D, 0x08,					// + 0x03			-> mov  ecx, [ebp + 0x08]			; move ExceptionInfo pointer into ecx
		0x85, 0xC9,							// + 0x06			-> test ecx, ecx					; check if ExceptionInfo pointer is non-zero
		0x74, 0x6D,							// + 0x08			-> je   0x77						; jump if nullptr

		0x8B, 0x09,							// + 0x0A			-> mov  ecx, [ecx]					; move EXCEPTION_POINTERS::ExceptionRecord into ecx
		0x85, 0xC9,							// + 0x0C			-> test ecx, ecx					; check if ExceptionRecord is non-zero
		0x74, 0x67,							// + 0x0E			-> je   0x77						; jump if nullptr

		0x81, 0x39, 0x01, 0x00, 0x00, 0x80,	// + 0x10			-> cmp  [ecx], 0x80000001			; check if ExceptionRecord::ExceptionCode matches EXCEPTION_GUARD_PAGE
		0x75, 0x5F,							// + 0x16			-> jne  0x77						; jump if not equal

		0x53,								// + 0x18			-> push ebx							; push ebx on stack (non volatile)
		0xBB, 0x00, 0x00, 0x00,	0x00,		// + 0x19 (+ 0x1A)	-> mov  ebx, 0x00000000				; load pData into ebx

		0x80, 0x3B, 0x00,					// + 0x1E			-> cmp  byte ptr [ebx], 0			; test if SR_REMOTE_DATA_VEH::Data::State is equal to SR_RS_ExecutionPending
		0x75, 0x53,							// + 0x22			-> jne  0x76						; jump if not equal

		0xC6, 0x03, 0x01,					// + 0x23			-> mov  byte ptr [ebx], 1			; set SR_REMOTE_DATA_VEH::Data::State to SR_RS_Executing

		0x83, 0x7B, 0x18, 0x00,				// + 0x26			-> cmp  dword ptr [ebx + 0x18], 0	; check if SR_REMOTE_DATA_VEH::pLdrProtectMrdata is non-zero
		0x74, 0x05,							// + 0x2A			-> je   0x31						; jump if nullptr
		0x6A, 0x00,							// + 0x2C			-> push 0							; push FALSE on the stack
		0xFF, 0x53, 0x18,					// + 0x2E			-> call dword ptr [ebx + 0x18]		; call LdrProtectMrdata to make LdrpVectorHandlerList writeable

		0x8B, 0x53, 0x1C,					// + 0x31			-> mov  edx, [ebx + 0x1C]			; move &LdrpVectorHandlerList.List (head) into edx
		0x8B, 0x0A,							// + 0x34			-> mov  ecx, [edx]					; move head->Flink into ecx (current)

		0x39, 0xD1,							// + 0x36			-> cmp  ecx, edx					; compare current, head
		0x74, 0x13,							// + 0x38			-> je   0x4D						; exit loop if equal (end of list)
		0x3B, 0x4B, 0x20,					// + 0x3A			-> cmp  ecx, [ebx + 0x20]			; compare current, SR_REMOTE_DATA_VEH::pFakeEntry
		0x74, 0x04,							// + 0x3D			-> je   0x43						; break loop if equal (found entry)
		0x8B, 0x09,							// + 0x3F			-> mov  ecx, [ecx]					; set current to current->Flink
		0xEB, 0xF3,							// + 0x41			-> jmp  0x36						; jmp to the start of the loop

		0x8B, 0x01,							// + 0x43			-> mov  eax, [ecx]					; store current->Flink in eax
		0x8B, 0x51, 0x04,					// + 0x45			-> mov  edx, [ecx + 0x04]			; store current->Blink in edx
		0x89, 0x02,							// + 0x48			-> mov  [edx], eax					; current->Blink->Flink = current->Fink
		0x89, 0x50, 0x04,					// + 0x4A			-> mov  [eax + 0x04], edx			; current->Flink->Blink = current->Blink

		0x83, 0x7B, 0x18, 0x00,				// + 0x4D			-> cmp  dword ptr [ebx + 0x18], 0	; check if SR_REMOTE_DATA_VEH::pLdrProtectMrdata is non-zero
		0x74, 0x05,							// + 0x51			-> je   0x48						; jump if nullptr
		0x6A, 0x01,							// + 0x53			-> push 1							; push TRUE on the stack
		0xFF, 0x53, 0x18,					// + 0x55			-> call dword ptr [ebx + 0x18]		; call LdrProtectMrdata to protect LdrpVectorHandlerList

		0xFF, 0x73, 0x0C,					// + 0x58			-> push [ebx + 0x0C]				; push pArg
		0xFF, 0x53, 0x10,					// + 0x5B			-> call dword ptr [ebx + 0x10]		; call pRoutine
		0x89, 0x43, 0x04,					// + 0x5E			-> mov  [ebx + 0x04], eax			; store returned value

		0x64, 0xA1, 0x18, 0x00, 0x00, 0x00,	// + 0x61			-> mov  eax, fs:[0x18]				; GetLastError
		0x8B, 0x40, 0x34,					// + 0x67			-> mov  eax, [eax + 0x34]
		0x89, 0x43, 0x08,					// + 0x6A			-> mov  [ebx + 0x08], eax			; store in SR_REMOTE_DATA_VEH::Data::LastWin32Error

		0xC6, 0x03, 0x02,					// + 0x6D			-> mov  byte ptr [ebx], 2			; set SR_REMOTE_DATA_VEH::Data::State to SR_RS_ExecutionFinished

		0x83, 0xC8, 0xFF,					// + 0x70			-> or   eax, -1						; set eax to EXCEPTION_CONTINUE_EXECUTION
		0x5B,								// + 0x73			-> pop  ebx							; restore ebx
		0xEB, 0x03,							// + 0x75			-> jmp  0x79						; jump to epilogue

		0x5B,								// + 0x76			-> pop  ebx							; restore ebx
		0x31, 0xC0, 						// + 0x77			-> xor  eax, eax					; set eax to EXCEPTION_CONTINUE_SEARCH

		0x5D,								// + 0x79			-> pop  ebp							; x86 __stdcall epilogue
		0xC2, 0x04, 0x00					// + 0x7A			-> ret  0x04
	}; // SIZE = 0x7D (+ sizeof(SR_REMOTE_DATA_VEH))

	*ReCa<void **>(Shellcode + 0x1A + sizeof(SR_REMOTE_DATA_VEH)) = pMem;

#endif

	void * pRemoteFunc = ReCa<BYTE *>(pMem) + sizeof(SR_REMOTE_DATA_VEH);

	auto * sr_data = ReCa<SR_REMOTE_DATA_VEH *>(Shellcode);
	sr_data->Data.pArg		= pArg;
	sr_data->Data.pRoutine	= pRoutine;
	
	LOG(2, "VEH will be called with:\n");
	LOG(3, "pRoutine = %p\n", pRemoteFunc);
	LOG(3, "pArg     = %p\n", pMem);

	auto * pVEHHead = &NATIVE::LdrpVectorHandlerList->List;
	LIST_ENTRY VEHHead{ 0 };

	if (!ReadProcessMemory(hTargetProc, pVEHHead, &VEHHead, sizeof(VEHHead), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "ReadProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		return SR_VEH_ERR_RPM_FAIL;
	}

	ProcessInfo PI;
	if (!PI.SetProcess(hTargetProc))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "Can't initialize ProcessInfo class\n");

		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_VEH_ERR_PROC_INFO_FAIL;
	}

	DWORD ProcessCookie = PI.GetProcessCookie();
	if (!ProcessCookie)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "Failed to resolve process cookie\n");

		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_VEH_ERR_PROCESS_COOKIE;
	}

	LOG(2, "ProcessCookie = %08X\n", ProcessCookie);

	auto EntrySize = 0;
	if (GetOSBuildVersion() >= g_Win10_2004)
	{
		EntrySize = sizeof(RTL_VECTORED_EXCEPTION_ENTRY_WIN10_2004);
	}
	else
	{
		EntrySize = sizeof(RTL_VECTORED_EXCEPTION_ENTRY);
	}

	BYTE * pNewEntry = ReCa<BYTE *>(VirtualAllocEx(hTargetProc, nullptr, EntrySize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (pNewEntry == nullptr)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "VirtualAllocEx failed: %08X\n", error_data.AdvErrorCode);

		return SR_VEH_ERR_CANT_ALLOC_MEM;
	}

	LOG(2, "Allocated memory for VEH entry:\n");
	LOG(3, "pNewEntry = %p\n", pNewEntry);

	auto pVEHShell_Encoded = ReCa<ULONG_PTR>(pRemoteFunc);
	pVEHShell_Encoded ^= ProcessCookie;

#ifdef _WIN64
	pVEHShell_Encoded = _rotr64(pVEHShell_Encoded, ProcessCookie & 0x3F);
#else
	pVEHShell_Encoded = _rotr(pVEHShell_Encoded, ProcessCookie & 0x1F);
#endif
	
	BYTE buffer[sizeof(RTL_VECTORED_EXCEPTION_ENTRY_WIN10_2004)]{ 0 };
	if (GetOSBuildVersion() >= g_Win10_2004)
	{
		auto NewEntry = ReCa<RTL_VECTORED_EXCEPTION_ENTRY_WIN10_2004 *>(buffer);
	
		NewEntry->List.Flink	= VEHHead.Flink;
		NewEntry->List.Blink	= pVEHHead;

		NewEntry->Flag			= 1;
		NewEntry->pFlag			= &ReCa<RTL_VECTORED_EXCEPTION_ENTRY_WIN10_2004 *>(pNewEntry)->Flag;

		NewEntry->VectoredHandler = ReCa<PVECTORED_EXCEPTION_HANDLER>(pVEHShell_Encoded);
	}
	else
	{
		auto NewEntry = ReCa<RTL_VECTORED_EXCEPTION_ENTRY *>(buffer);

		NewEntry->List.Flink = VEHHead.Flink;
		NewEntry->List.Blink = pVEHHead;

		NewEntry->Flag = 1;

		NewEntry->VectoredHandler = ReCa<PVECTORED_EXCEPTION_HANDLER>(pVEHShell_Encoded);
	}

	sr_data->pLdrProtectMrdata	= NATIVE::LdrProtectMrdata;
	sr_data->pListHead			= pVEHHead;
	sr_data->pFakeEntry			= ReCa<LIST_ENTRY *>(pNewEntry);

	if (!WriteProcessMemory(hTargetProc, pNewEntry, &buffer, EntrySize, nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		VirtualFreeEx(hTargetProc, pNewEntry, 0, MEM_RELEASE);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_VEH_ERR_WPM_FAIL;
	}

	LOG(2, "Copied fake VEH entry into target process\n");

	if (!WriteProcessMemory(hTargetProc, pMem, Shellcode, sizeof(Shellcode), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		VirtualFreeEx(hTargetProc, pNewEntry, 0, MEM_RELEASE);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_VEH_ERR_WPM_FAIL;
	}

	LOG(2, "Copied shellcode into target process\n");

	auto pPEB = PI.GetPEB();

	if (!pPEB)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "Failed to get PEB pointer\n");

		VirtualFreeEx(hTargetProc, pNewEntry, 0, MEM_RELEASE);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_VEH_ERR_CANT_GET_PEB;
	}

	PEB peb{ 0 };
	if (!ReadProcessMemory(hTargetProc, pPEB, &peb, sizeof(PEB), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "ReadProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		VirtualFreeEx(hTargetProc, pNewEntry, 0, MEM_RELEASE);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_VEH_ERR_RPM_FAIL;
	}

	bool updated_peb = false;
	if (peb.ProcessUsingVEH == FALSE)
	{
		LOG(2, "Updating PEB::ProcessUsingVEH flag\n");

		peb.ProcessUsingVEH = TRUE;

		if (!WriteProcessMemory(hTargetProc, &pPEB->CrossProcessFlags, &peb.CrossProcessFlags, sizeof(peb.CrossProcessFlags), nullptr))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(2, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

			VirtualFreeEx(hTargetProc, pNewEntry, 0, MEM_RELEASE);
			VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

			return SR_VEH_ERR_WPM_FAIL;
		}

		updated_peb = true;
	}

	DWORD dwOld1 = 0;
	DWORD dwOld2 = 0;
	if (!VirtualProtectEx(hTargetProc, pVEHHead, sizeof(LIST_ENTRY), PAGE_READWRITE, &dwOld1))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "VirtualProtectEx failed: %08X\n", error_data.AdvErrorCode);

		if (updated_peb)
		{
			peb.ProcessUsingVEH = FALSE;
			WriteProcessMemory(hTargetProc, &pPEB->CrossProcessFlags, &peb.CrossProcessFlags, sizeof(peb.CrossProcessFlags), nullptr);
		}

		VirtualFreeEx(hTargetProc, pNewEntry, 0, MEM_RELEASE);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_VEH_ERR_WPM_FAIL;
	}
		
	if (!WriteProcessMemory(hTargetProc, pVEHHead, &pNewEntry, sizeof(pNewEntry), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		VirtualProtectEx(hTargetProc, pVEHHead, sizeof(LIST_ENTRY), dwOld1, &dwOld2);

		if (updated_peb)
		{
			peb.ProcessUsingVEH = FALSE;
			WriteProcessMemory(hTargetProc, &pPEB->CrossProcessFlags, &peb.CrossProcessFlags, sizeof(peb.CrossProcessFlags), nullptr);
		}

		VirtualFreeEx(hTargetProc, pNewEntry, 0, MEM_RELEASE);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_VEH_ERR_WPM_FAIL;
	}

	if (!WriteProcessMemory(hTargetProc, &VEHHead.Flink->Blink, &pNewEntry, sizeof(pNewEntry), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		VirtualProtectEx(hTargetProc, pVEHHead, sizeof(LIST_ENTRY), PAGE_READWRITE, &dwOld2);

		WriteProcessMemory(hTargetProc, pVEHHead, &VEHHead.Flink, sizeof(VEHHead.Flink), nullptr);

		VirtualProtectEx(hTargetProc, pVEHHead, sizeof(LIST_ENTRY), dwOld1, &dwOld2);

		if (updated_peb)
		{
			peb.ProcessUsingVEH = FALSE;
			WriteProcessMemory(hTargetProc, &pPEB->CrossProcessFlags, &peb.CrossProcessFlags, sizeof(peb.CrossProcessFlags), nullptr);
		}

		VirtualFreeEx(hTargetProc, pNewEntry, 0, MEM_RELEASE);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_VEH_ERR_WPM_FAIL;
	}

	LOG(2, "VEH handler linked to LdrpVectorHandlerList\n");

	if (!VirtualProtectEx(hTargetProc, NATIVE::NtDelayExecution, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &dwOld2))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "VirtualProtectEx failed: %08X\n", error_data.AdvErrorCode);

		VirtualProtectEx(hTargetProc, pVEHHead, sizeof(LIST_ENTRY), PAGE_READWRITE, &dwOld2);
		
		WriteProcessMemory(hTargetProc, &VEHHead.Flink->Blink, &pVEHHead, sizeof(pVEHHead), nullptr);
		WriteProcessMemory(hTargetProc, pVEHHead, &VEHHead.Flink, sizeof(VEHHead.Flink), nullptr);

		VirtualProtectEx(hTargetProc, pVEHHead, sizeof(LIST_ENTRY), dwOld1, &dwOld2);

		if (updated_peb)
		{
			peb.ProcessUsingVEH = FALSE;
			WriteProcessMemory(hTargetProc, &pPEB->CrossProcessFlags, &peb.CrossProcessFlags, sizeof(peb.CrossProcessFlags), nullptr);
		}

		VirtualFreeEx(hTargetProc, pNewEntry, 0, MEM_RELEASE);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_VEH_ERR_PROTECT_FAIL;
	}

	LOG(2, "Entering wait state\n");

	Sleep(SR_REMOTE_DELAY);

	SR_REMOTE_DATA data{ };
	data.State			= SR_REMOTE_STATE::SR_RS_ExecutionPending;
	data.Ret			= ERROR_SUCCESS;
	data.LastWin32Error = ERROR_SUCCESS;

	auto Timer = GetTickCount64();
	while (GetTickCount64() - Timer < Timeout)
	{
		auto dwWaitRet = WaitForSingleObject(g_hInterruptEvent, 10);

		auto bRet = ReadProcessMemory(hTargetProc, pMem, &data, sizeof(data), nullptr);
		if (bRet)
		{
			if (data.State == SR_REMOTE_STATE::SR_RS_ExecutionFinished)
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
			}
			else
			{
				LOG(2, "ReadProcessMemory failed: %08X\n", error_data.AdvErrorCode);
			}

			VirtualProtectEx(hTargetProc, pVEHHead, sizeof(LIST_ENTRY), PAGE_READWRITE, &dwOld2);

			WriteProcessMemory(hTargetProc, &VEHHead.Flink->Blink, &pVEHHead, sizeof(pVEHHead), nullptr);
			WriteProcessMemory(hTargetProc, pVEHHead, &VEHHead.Flink, sizeof(VEHHead.Flink), nullptr);

			VirtualProtectEx(hTargetProc, pVEHHead, sizeof(LIST_ENTRY), dwOld1, &dwOld2);

			if (updated_peb)
			{
				peb.ProcessUsingVEH = FALSE;
				WriteProcessMemory(hTargetProc, &pPEB->CrossProcessFlags, &peb.CrossProcessFlags, sizeof(peb.CrossProcessFlags), nullptr);
			}

			VirtualFreeEx(hTargetProc, pNewEntry, 0, MEM_RELEASE);
			VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

			if (dwWaitRet == WAIT_OBJECT_0)
			{
				SetEvent(g_hInterruptedEvent);

				return SR_ERR_INTERRUPT;
			}

			return SR_VEH_ERR_RPM_FAIL;
		}
	}

	VirtualFreeEx(hTargetProc, pNewEntry, 0, MEM_RELEASE);

	if (data.State != SR_REMOTE_STATE::SR_RS_ExecutionFinished)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "Shell timed out\n");		

		return SR_VEH_ERR_REMOTE_TIMEOUT;
	}

	VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

	LOG(2, "pRoutine returned: %08X\n", data.Ret);

	Out = data.Ret;

	return SR_ERR_SUCCESS;
}