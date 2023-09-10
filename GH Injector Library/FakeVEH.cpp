/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

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
							if (data->remove_VEH_flag)
							{
								#ifdef _WIN64
									PEB * peb = reinterpret_cast<PEB *>(__readgsqword(0x60));
								#else
									PEB * peb = reinterpret_cast<PEB *>(__readfsdword(0x30));
								#endif

								peb->ProcessUsingVEH = FALSE;
							}

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

		0x48, 0x85, 0xC9,										// + 0x00	-> test rcx, rcx						; check if rcx (ExceptionInfo pointer) is non-zero
		0x0F, 0x84, 0xB4, 0x00, 0x00, 0x00,						// + 0x03	-> je	0xBD							; jump if nullptr

		0x48, 0x8B, 0x09,										// + 0x09	-> mov	rcx, [rcx]						; move EXCEPTION_POINTERS::ExceptionRecord into rcx
		0x48, 0x85, 0xC9,										// + 0x0C	-> test rcx, rcx						; check if ExceptionRecord is non-zero
		0x0F, 0x84, 0xA8, 0x00, 0x00, 0x00,						// + 0x0F	-> je	0xBD							; jump if nullptr

		0x81, 0x39, 0x01, 0x00, 0x00, 0x80,						// + 0x15	-> cmp	dword ptr [rcx], 0x80000001		; check if ExceptionRecord::ExceptionCode matches EXCEPTION_GUARD_PAGE
		0x0F, 0x85, 0x9C, 0x00, 0x00, 0x00,						// + 0x1B	-> jne	0xBD							; jump if not equal

		0x53,													// + 0x21	-> push rbx								; push rbx on stack (non volatile)
		0x48, 0x8D, 0x1D, 0x87, 0xFF, 0xFF, 0xFF,				// + 0x22	-> lea	rbx, [-0x50]					; load pData into rbx

		0x80, 0x3B, 0x00,										// + 0x29	-> cmp	byte ptr [rbx], 0				; test if SR_REMOTE_DATA::State is equal to SR_RS_ExecutionPending
		0x0F, 0x85, 0x8A, 0x00, 0x00, 0x00,						// + 0x2C	-> jne	0xBC							; jump if not equal

		0xC6, 0x03, 0x01,										// + 0x32	-> mov	byte ptr [rbx], 1				; set SR_REMOTE_DATA::State to SR_RS_Executing
		
		0x80, 0x7B, 0x48, 0x01,									// + 0x35	-> cmp  byte ptr [rbx + 0x48], 1		; test if SR_REMOTE_DATA::bRemoveVEHBit is set
		0x75, 0x0D,												// + 0x39	-> jne  0x48							; jump if not equal
		0x65, 0x48, 0x8B, 0x0C, 0x25, 0x60, 0x00, 0x00, 0x00,	// + 0x3B	-> mov  rcx, gs: [0x60]					; mov PEB pointer into rcx
		0x83, 0x71, 0x50, 0x04,									// + 0x44	-> xor  dword ptr [rcx + 0x50], 0x04	; remove PEB->ProcessUsingVEH bit

		0x48, 0x83, 0x7B, 0x30, 0x00,							// + 0x48	-> cmp  qword ptr [rbx + 0x30], 0		; check if SR_REMOTE_DATA_VEH::pLdrProtectMrdata is non-zero
		0x74, 0x0A,												// + 0x4D	-> je   0x59							; jump if nullptr
		0x48, 0x31, 0xC9,										// + 0x4F	-> xor  rcx, rcx						; move FALSE into rcx
		0x48, 0x83, 0xEC, 0x20,									// + 0x52	-> sub  rsp, 0x20						; reserve 0x20 bytes on the stack
		0xFF, 0x53, 0x30,										// + 0x56	-> call qword ptr [rbx + 0x30]			; call LdrProtectMrdata to make LdrpVectorHandlerList writeable

		0x48, 0x8B, 0x53, 0x38,									// + 0x59	-> mov  rdx, [rbx + 0x38]				; move &LdrpVectorHandlerList.List (head) into rdx
		0x48, 0x8B, 0x0A,										// + 0x5D	-> mov  rcx, [rdx]						; move head->Flink into rcx (current)

		0x48, 0x39, 0xD1,										// + 0x60	-> cmp  rcx, rdx						; compare current, head
		0x74, 0x19,												// + 0x63	-> je   0x7E							; exit loop if equal (end of list)
		0x48, 0x3B, 0x4B, 0x40,									// + 0x65	-> cmp  rcx, [rbx + 0x40]				; compare current, SR_REMOTE_DATA_VEH::pFakeEntry
		0x74, 0x05,												// + 0x69	-> je   0x70							; break loop if equal (found entry)
		0x48, 0x8B, 0x09,										// + 0x6B	-> mov  rcx, [rcx]						; set current to current->Flink
		0xEB, 0xF0,												// + 0x6E	-> jmp  0x60							; jmp to the start of the loop

		0x48, 0x8B, 0x01,										// + 0x70	-> mov  rax, [rcx]						; store current->Flink in rax
		0x48, 0x8B, 0x51, 0x08,									// + 0x73	-> mov  rdx, [rcx + 0x08]				; store current->Blink in rdx
		0x48, 0x89, 0x02,										// + 0x77	-> mov  [rdx], rax						; current->Blink->Flink = current->Fink
		0x48, 0x89, 0x50, 0x08,									// + 0x7A	-> mov  [rax + 0x08], rdx				; current->Flink->Blink = current->Blink

		0x48, 0x83, 0x7B, 0x30, 0x00,							// + 0x7E	-> cmp  qword ptr [rbx + 0x30], 0		; check if SR_REMOTE_DATA_VEH::pLdrProtectMrdata is non-zero
		0x74, 0x0C,												// + 0x83	-> je   0x91							; jump if nullptr
		0x48, 0x31, 0xC9,										// + 0x85	-> xor  rcx, rcx						; zero rcx
		0xB1, 0x01,												// + 0x88	-> mov  cl, 1							; move TRUE into rcx
		0xFF, 0x53, 0x30,										// + 0x8A	-> call qword ptr [rbx + 0x30]			; call LdrProtectMrdata to protect LdrpVectorHandlerList
		0x48, 0x83, 0xC4, 0x20,									// + 0x8D	-> add  rsp, 0x20						; restore stack (reserved at + 0x3B)

		0x48, 0x8B, 0x4B, 0x18,									// + 0x91	-> mov	rcx, [rbx + 0x18]				; move pArg into rcx
		0x48, 0x83, 0xEC, 0x20,									// + 0x95	-> sub	rsp, 0x20						; reserve stack
		0xFF, 0x53, 0x20,										// + 0x99	-> call qword ptr [rbx + 0x20]			; call pRoutine
		0x48, 0x83, 0xC4, 0x20,									// + 0x9C	-> add	rsp, 0x20						; update stack
		0x48, 0x89, 0x43, 0x08,									// + 0xA0	-> mov	[rbx + 0x08], rax				; store returned value

		0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,	// + 0xA4	-> mov	rax, gs: [0x30]					; GetLastError
		0x8B, 0x40, 0x68,										// + 0xAD	-> mov	eax, [rax + 0x68]
		0x89, 0x43, 0x10,										// + 0xB0	-> mov	[rbx + 0x10], eax				; store in SR_REMOTE_DATA::LastWin32Error

		0xC6, 0x03, 0x02,										// + 0xB3	-> mov	byte ptr [rbx], 2				; set SR_REMOTE_DATA::State to SR_RS_ExecutionFinished

		0x83, 0xC8, 0xFF,										// + 0xB6	-> or	eax, -1							; set eax to EXCEPTION_CONTINUE_EXECUTION
		0x5B,													// + 0xB9	-> pop	rbx								; restore rbx
		0xEB, 0x04,												// + 0xBA	-> jmp	0xC0							; jump to ret

		0x5B,													// + 0xBC	-> pop	rbx								; restore rbx			
		0x48, 0x31, 0xC0,										// + 0xBD	-> xor	rax, rax						; set rax to EXCEPTION_CONTINUE_SEARCH

		0xC3													// + 0xC0	-> ret									; return

	}; // SIZE = 0xC1 (+ sizeof(SR_REMOTE_DATA_VEH))
	
#else

	BYTE Shellcode[] =
	{
		SR_REMOVE_DATA_BUFFER_VEH

		0x55,								// + 0x00			-> push ebp								; x86 stack frame creation
		0x8B, 0xEC,							// + 0x01			-> mov  ebp, esp

		0x8B, 0x4D, 0x08,					// + 0x03			-> mov  ecx, [ebp + 0x08]				; move ExceptionInfo pointer into ecx
		0x85, 0xC9,							// + 0x06			-> test ecx, ecx						; check if ExceptionInfo pointer is non-zero
		0x0F, 0x84, 0x7D, 0x00, 0x00, 0x00,	// + 0x08			-> je   0x8B							; jump if nullptr

		0x8B, 0x09,							// + 0x0D			-> mov  ecx, [ecx]						; move EXCEPTION_POINTERS::ExceptionRecord into ecx
		0x85, 0xC9,							// + 0x10			-> test ecx, ecx						; check if ExceptionRecord is non-zero
		0x74, 0x77,							// + 0x12			-> je   0x8B							; jump if nullptr

		0x81, 0x39, 0x01, 0x00, 0x00, 0x80,	// + 0x14			-> cmp  [ecx], 0x80000001				; check if ExceptionRecord::ExceptionCode matches EXCEPTION_GUARD_PAGE
		0x75, 0x6F,							// + 0x1A			-> jne  0x8B							; jump if not equal

		0x53,								// + 0x1C			-> push ebx								; push ebx on stack (non volatile)
		0xBB, 0x00, 0x00, 0x00,	0x00,		// + 0x1D (+ 0x1E)	-> mov  ebx, 0x00000000					; load pData into ebx

		0x80, 0x3B, 0x00,					// + 0x22			-> cmp  byte ptr [ebx], 0				; test if SR_REMOTE_DATA_VEH::Data::State is equal to SR_RS_ExecutionPending
		0x75, 0x63,							// + 0x25			-> jne  0x8A							; jump if not equal

		0xC6, 0x03, 0x01,					// + 0x27			-> mov  byte ptr [ebx], 1				; set SR_REMOTE_DATA_VEH::Data::State to SR_RS_Executing

		0x80, 0x7B, 0x24, 0x01,				// + 0x2A			-> cmp  byte ptr [ebx + 0x24], 1		: test if SR_REMOTE_DATA::bRemoveVEHBit is set
		0x75, 0x10,							// + 0x2E			-> jne  0x40							: jump if not equal
		0x64, 0xA1, 0x30, 0x00, 0x00, 0x00,	// + 0x30			-> mov  eax, fs:[0x30]					: mov PEB pointer into ecx
		0x83, 0x70, 0x28, 0x04,				// + 0x36			-> xor  dword ptr [ecx + 0x28], 0x04	: remove PEB->ProcessUsingVEH bit

		0x83, 0x7B, 0x18, 0x00,				// + 0x3A			-> cmp  dword ptr [ebx + 0x18], 0		; check if SR_REMOTE_DATA_VEH::pLdrProtectMrdata is non-zero
		0x74, 0x05,							// + 0x3E			-> je   0x45							; jump if nullptr
		0x6A, 0x00,							// + 0x40			-> push 0								; push FALSE on the stack
		0xFF, 0x53, 0x18,					// + 0x42			-> call dword ptr [ebx + 0x18]			; call LdrProtectMrdata to make LdrpVectorHandlerList writeable

		0x8B, 0x53, 0x1C,					// + 0x45			-> mov  edx, [ebx + 0x1C]				; move &LdrpVectorHandlerList.List (head) into edx
		0x8B, 0x0A,							// + 0x48			-> mov  ecx, [edx]						; move head->Flink into ecx (current)

		0x39, 0xD1,							// + 0x4A			-> cmp  ecx, edx						; compare current, head
		0x74, 0x13,							// + 0x4C			-> je   0x61							; exit loop if equal (end of list)
		0x3B, 0x4B, 0x20,					// + 0x4E			-> cmp  ecx, [ebx + 0x20]				; compare current, SR_REMOTE_DATA_VEH::pFakeEntry
		0x74, 0x04,							// + 0x51			-> je   0x57							; break loop if equal (found entry)
		0x8B, 0x09,							// + 0x53			-> mov  ecx, [ecx]						; set current to current->Flink
		0xEB, 0xF3,							// + 0x55			-> jmp  0x4A							; jmp to the start of the loop

		0x8B, 0x01,							// + 0x57			-> mov  eax, [ecx]						; store current->Flink in eax
		0x8B, 0x51, 0x04,					// + 0x59			-> mov  edx, [ecx + 0x04]				; store current->Blink in edx
		0x89, 0x02,							// + 0x5C			-> mov  [edx], eax						; current->Blink->Flink = current->Fink
		0x89, 0x50, 0x04,					// + 0x5E			-> mov  [eax + 0x04], edx				; current->Flink->Blink = current->Blink

		0x83, 0x7B, 0x18, 0x00,				// + 0x61			-> cmp  dword ptr [ebx + 0x18], 0		; check if SR_REMOTE_DATA_VEH::pLdrProtectMrdata is non-zero
		0x74, 0x05,							// + 0x65			-> je   0x6C							; jump if nullptr
		0x6A, 0x01,							// + 0x67			-> push 1								; push TRUE on the stack
		0xFF, 0x53, 0x18,					// + 0x69			-> call dword ptr [ebx + 0x18]			; call LdrProtectMrdata to protect LdrpVectorHandlerList

		0xFF, 0x73, 0x0C,					// + 0x6C			-> push [ebx + 0x0C]					; push pArg
		0xFF, 0x53, 0x10,					// + 0x6F			-> call dword ptr [ebx + 0x10]			; call pRoutine
		0x89, 0x43, 0x04,					// + 0x72			-> mov  [ebx + 0x04], eax				; store returned value

		0x64, 0xA1, 0x18, 0x00, 0x00, 0x00,	// + 0x75			-> mov  eax, fs:[0x18]					; GetLastError
		0x8B, 0x40, 0x34,					// + 0x7B			-> mov  eax, [eax + 0x34]
		0x89, 0x43, 0x08,					// + 0x7E			-> mov  [ebx + 0x08], eax				; store in SR_REMOTE_DATA_VEH::Data::LastWin32Error

		0xC6, 0x03, 0x02,					// + 0x81			-> mov  byte ptr [ebx], 2				; set SR_REMOTE_DATA_VEH::Data::State to SR_RS_ExecutionFinished

		0x83, 0xC8, 0xFF,					// + 0x84			-> or   eax, -1							; set eax to EXCEPTION_CONTINUE_EXECUTION
		0x5B,								// + 0x87			-> pop  ebx								; restore ebx
		0xEB, 0x03,							// + 0x88			-> jmp  0x8D							; jump to epilogue

		0x5B,								// + 0x8A			-> pop  ebx								; restore ebx
		0x31, 0xC0, 						// + 0x8B			-> xor  eax, eax						; set eax to EXCEPTION_CONTINUE_SEARCH

		0x5D,								// + 0x8D			-> pop  ebp								; x86 __stdcall epilogue
		0xC2, 0x04, 0x00					// + 0x8E			-> ret  0x04
	}; // SIZE = 0x91 (+ sizeof(SR_REMOTE_DATA_VEH))

	*ReCa<void **>(Shellcode + 0x1E + sizeof(SR_REMOTE_DATA_VEH)) = pMem;

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
	sr_data->bRemoveVEHBit		= FALSE;

	if (!WriteProcessMemory(hTargetProc, pNewEntry, &buffer, EntrySize, nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		VirtualFreeEx(hTargetProc, pNewEntry, 0, MEM_RELEASE);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_VEH_ERR_WPM_FAIL;
	}

	LOG(2, "Copied fake VEH entry into target process\n");

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

	DWORD dwOld1 = 0;
	DWORD dwOld2 = 0;
	if (!VirtualProtectEx(hTargetProc, pVEHHead, sizeof(LIST_ENTRY), PAGE_READWRITE, &dwOld1))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "VirtualProtectEx failed: %08X\n", error_data.AdvErrorCode);

		VirtualFreeEx(hTargetProc, pNewEntry, 0, MEM_RELEASE);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_VEH_ERR_WPM_FAIL;
	}
		
	if (!WriteProcessMemory(hTargetProc, pVEHHead, &pNewEntry, sizeof(pNewEntry), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		VirtualProtectEx(hTargetProc, pVEHHead, sizeof(LIST_ENTRY), dwOld1, &dwOld2);

		VirtualFreeEx(hTargetProc, pNewEntry, 0, MEM_RELEASE);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_VEH_ERR_WPM_FAIL;
	}

	DWORD dwOld3 = 0;
	DWORD dwOld4 = 0;
	LIST_ENTRY * pFlink = VEHHead.Flink;
	if (!VirtualProtectEx(hTargetProc, pFlink, sizeof(LIST_ENTRY), PAGE_READWRITE, &dwOld3))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		VirtualProtectEx(hTargetProc, pFlink, sizeof(LIST_ENTRY), dwOld3, &dwOld4);

		VirtualProtectEx(hTargetProc, pVEHHead, sizeof(LIST_ENTRY), PAGE_READWRITE, &dwOld2);
		WriteProcessMemory(hTargetProc, pVEHHead, &VEHHead.Flink, sizeof(DWORD), nullptr);
		VirtualProtectEx(hTargetProc, pVEHHead, sizeof(LIST_ENTRY), dwOld1, &dwOld2);

		VirtualFreeEx(hTargetProc, pNewEntry, 0, MEM_RELEASE);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_VEH_ERR_PROTECT_FAIL;
	}

	if (!WriteProcessMemory(hTargetProc, &VEHHead.Flink->Blink, &pNewEntry, sizeof(pNewEntry), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		VirtualProtectEx(hTargetProc, pVEHHead, sizeof(LIST_ENTRY), PAGE_READWRITE, &dwOld2);
		WriteProcessMemory(hTargetProc, pVEHHead, &VEHHead.Flink, sizeof(VEHHead.Flink), nullptr);
		VirtualProtectEx(hTargetProc, pVEHHead, sizeof(LIST_ENTRY), dwOld1, &dwOld2);

		VirtualFreeEx(hTargetProc, pNewEntry, 0, MEM_RELEASE);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_VEH_ERR_WPM_FAIL;
	}

	LOG(2, "VEH handler linked to LdrpVectorHandlerList\n");

	if (peb.ProcessUsingVEH == FALSE)
	{
		sr_data->bRemoveVEHBit = TRUE;
	}

	if (!WriteProcessMemory(hTargetProc, pMem, Shellcode, sizeof(Shellcode), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		VirtualFreeEx(hTargetProc, pNewEntry, 0, MEM_RELEASE);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_VEH_ERR_WPM_FAIL;
	}

	LOG(2, "Copied shellcode into target process\n");

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

	if (!VirtualProtectEx(hTargetProc, NATIVE::NtDelayExecution, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &dwOld2))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "VirtualProtectEx failed: %08X\n", error_data.AdvErrorCode);


		VirtualProtectEx(hTargetProc, pFlink, sizeof(LIST_ENTRY), PAGE_READWRITE, &dwOld4);
		WriteProcessMemory(hTargetProc, &pFlink->Blink, &pVEHHead, sizeof(pVEHHead), nullptr);
		VirtualProtectEx(hTargetProc, pFlink, sizeof(LIST_ENTRY), dwOld3, &dwOld4);

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

			VirtualProtectEx(hTargetProc, pFlink, sizeof(LIST_ENTRY), PAGE_READWRITE, &dwOld4);
			WriteProcessMemory(hTargetProc, &pFlink->Blink, &pVEHHead, sizeof(DWORD), nullptr);
			VirtualProtectEx(hTargetProc, pFlink, sizeof(LIST_ENTRY), dwOld3, &dwOld4);

			VirtualProtectEx(hTargetProc, pVEHHead, sizeof(LIST_ENTRY), PAGE_READWRITE, &dwOld2);
			WriteProcessMemory(hTargetProc, pVEHHead, &VEHHead.Flink, sizeof(DWORD), nullptr);
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