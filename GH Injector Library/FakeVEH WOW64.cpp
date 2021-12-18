#include "pch.h"

#ifdef _WIN64

#include "Start Routine.h"

DWORD SR_FakeVEH_WOW64(HANDLE hTargetProc, f_Routine_WOW64 pRoutine, DWORD pArg, DWORD & Out, DWORD Timeout, ERROR_DATA & error_data)
{
	LOG(2, "Begin SR_FakeVEH\n");

	void * pMem = VirtualAllocEx(hTargetProc, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pMem)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "VirtualAllocEx failed: %08X\n", error_data.AdvErrorCode);

		return SR_VEH_ERR_CANT_ALLOC_MEM;
	}

	BYTE Shellcode[] =
	{
		SR_REMOTE_DATA_BUFFER_VEH_86

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
		0xBB, 0x00, 0x00, 0x00, 0x00,		// + 0x19 (+ 0x1A)	-> mov  ebx, 0x00000000				; load pData into ebx

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
		0x3B, 0x4B, 0x20,					// + 0x3A			-> cmp  ecx, [ebx + 0x20]			; compare current to SR_REMOTE_DATA_VEH::pFakeEntry
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
	}; // SIZE = 0x7D (+ sizeof(SR_REMOTE_DATA_VEH_WOW64))

	*ReCa<DWORD *>(Shellcode + 0x1A + sizeof(SR_REMOTE_DATA_VEH_WOW64)) = MDWD(pMem);

	DWORD pRemoteFunc = MDWD(pMem) + sizeof(SR_REMOTE_DATA_VEH_WOW64);

	auto * sr_data = ReCa<SR_REMOTE_DATA_VEH_WOW64 *>(Shellcode);
	sr_data->Data.pArg		= pArg;
	sr_data->Data.pRoutine	= pRoutine;

	LOG(2, "VEH will be called with:\n");
	LOG(3, "pRoutine = %p\n", pRemoteFunc);
	LOG(3, "pArg     = %p\n", pMem);

	auto * pVEHHead = &ReCa<RTL_VECTORED_HANDLER_LIST_32 *>(MPTR(WOW64::LdrpVectorHandlerList_WOW64))->List;
	LIST_ENTRY32 VEHHead{ 0 };

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
		EntrySize = sizeof(RTL_VECTORED_EXCEPTION_ENTRY_WIN10_2004_32);
	}
	else
	{
		EntrySize = sizeof(RTL_VECTORED_EXCEPTION_ENTRY_32);
	}

	BYTE * pNewEntry = ReCa<BYTE *>(VirtualAllocEx(hTargetProc, nullptr, EntrySize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (pNewEntry == nullptr)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "VirtualAllocEx failed: %08X\n", error_data.AdvErrorCode);

		return SR_VEH_ERR_CANT_ALLOC_MEM;
	}

	LOG(2, "Allocated memory for VEH entry at\n");
	LOG(3, "pNewEntry = %p\n", pNewEntry);

	auto pVEHShell_Encoded = MDWD(pRemoteFunc);
	pVEHShell_Encoded ^= ProcessCookie;
	pVEHShell_Encoded = _rotr(pVEHShell_Encoded, ProcessCookie & 0x1F);

	BYTE buffer[sizeof(RTL_VECTORED_EXCEPTION_ENTRY_WIN10_2004_32)]{ 0 };
	if (GetOSBuildVersion() >= g_Win10_2004)
	{
		auto NewEntry = ReCa<RTL_VECTORED_EXCEPTION_ENTRY_WIN10_2004_32 *>(buffer);
	
		NewEntry->List.Flink	= VEHHead.Flink;
		NewEntry->List.Blink	= MDWD(pVEHHead);

		NewEntry->Flag			= 1;
		NewEntry->pFlag			= MDWD(&ReCa<RTL_VECTORED_EXCEPTION_ENTRY_WIN10_2004_32 *>(pNewEntry)->Flag);

		NewEntry->VectoredHandler = pVEHShell_Encoded;
	}
	else
	{
		auto NewEntry = ReCa<RTL_VECTORED_EXCEPTION_ENTRY_32 *>(buffer);

		NewEntry->List.Flink = VEHHead.Flink;
		NewEntry->List.Blink = MDWD(pVEHHead);

		NewEntry->Flag = 1;

		NewEntry->VectoredHandler = pVEHShell_Encoded;
	}

	sr_data->pLdrProtectMrdata	= WOW64::LdrProtectMrdata_WOW64;
	sr_data->pListHead			= MDWD(pVEHHead);
	sr_data->pFakeEntry			= MDWD(pNewEntry);

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

	auto pPEB = PI.GetPEB_WOW64();

	if (!pPEB)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "Failed to get PEB pointer\n");

		VirtualFreeEx(hTargetProc, pNewEntry, 0, MEM_RELEASE);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_VEH_ERR_CANT_GET_PEB;
	}

	PEB_32 peb{ 0 };
	if (!ReadProcessMemory(hTargetProc, pPEB, &peb, sizeof(peb), nullptr))
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
	if (!VirtualProtectEx(hTargetProc, pVEHHead, sizeof(LIST_ENTRY32), PAGE_READWRITE, &dwOld1))
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

	if (!WriteProcessMemory(hTargetProc, &pVEHHead->Flink, &pNewEntry, sizeof(DWORD), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		VirtualProtectEx(hTargetProc, pVEHHead, sizeof(LIST_ENTRY32), dwOld1, &dwOld2);

		if (updated_peb)
		{
			peb.ProcessUsingVEH = FALSE;
			WriteProcessMemory(hTargetProc, &pPEB->CrossProcessFlags, &peb.CrossProcessFlags, sizeof(peb.CrossProcessFlags), nullptr);
		}

		VirtualFreeEx(hTargetProc, pNewEntry, 0, MEM_RELEASE);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_VEH_ERR_WPM_FAIL;
	}
	
	DWORD dwOld3 = 0;
	DWORD dwOld4 = 0;
	LIST_ENTRY32 * pFlink = ReCa<LIST_ENTRY32 *>(MPTR(VEHHead.Flink));
	if (!VirtualProtectEx(hTargetProc, pFlink, sizeof(DWORD), PAGE_READWRITE, &dwOld3))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		VirtualProtectEx(hTargetProc, pVEHHead, sizeof(LIST_ENTRY32), PAGE_READWRITE, &dwOld2);
		WriteProcessMemory(hTargetProc, pVEHHead, &VEHHead.Flink, sizeof(DWORD), nullptr);
		VirtualProtectEx(hTargetProc, pVEHHead, sizeof(LIST_ENTRY32), dwOld1, &dwOld2);

		if (updated_peb)
		{
			peb.ProcessUsingVEH = FALSE;
			WriteProcessMemory(hTargetProc, &pPEB->CrossProcessFlags, &peb.CrossProcessFlags, sizeof(peb.CrossProcessFlags), nullptr);
		}

		VirtualFreeEx(hTargetProc, pNewEntry, 0, MEM_RELEASE);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_VEH_ERR_PROTECT_FAIL;
	}

	if (!WriteProcessMemory(hTargetProc, &pFlink->Blink, &pNewEntry, sizeof(DWORD), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		VirtualProtectEx(hTargetProc, pFlink, sizeof(DWORD), dwOld3, &dwOld4);

		VirtualProtectEx(hTargetProc, pVEHHead, sizeof(LIST_ENTRY32), PAGE_READWRITE, &dwOld2);
		WriteProcessMemory(hTargetProc, pVEHHead, &VEHHead.Flink, sizeof(DWORD), nullptr);
		VirtualProtectEx(hTargetProc, pVEHHead, sizeof(LIST_ENTRY32), dwOld1, &dwOld2);

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

	if (!VirtualProtectEx(hTargetProc, MPTR(WOW64::NtDelayExecution_WOW64), 1, PAGE_EXECUTE_READ | PAGE_GUARD, &dwOld2))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "VirtualProtectEx failed: %08X\n", error_data.AdvErrorCode);

		VirtualProtectEx(hTargetProc, pFlink, sizeof(DWORD), PAGE_READWRITE, &dwOld4);
		WriteProcessMemory(hTargetProc, &pFlink->Blink, &pVEHHead, sizeof(DWORD), nullptr);
		VirtualProtectEx(hTargetProc, pFlink, sizeof(DWORD), dwOld3, &dwOld4);

		VirtualProtectEx(hTargetProc, pVEHHead, sizeof(LIST_ENTRY32), PAGE_READWRITE, &dwOld2);
		WriteProcessMemory(hTargetProc, pVEHHead, &VEHHead.Flink, sizeof(DWORD), nullptr);
		VirtualProtectEx(hTargetProc, pVEHHead, sizeof(LIST_ENTRY32), dwOld1, &dwOld2);

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
			
			VirtualProtectEx(hTargetProc, pFlink, sizeof(DWORD), PAGE_READWRITE, &dwOld4);
			WriteProcessMemory(hTargetProc, &pFlink->Blink, &pVEHHead, sizeof(DWORD), nullptr);
			VirtualProtectEx(hTargetProc, pFlink, sizeof(DWORD), dwOld3, &dwOld4);
			
			VirtualProtectEx(hTargetProc, pVEHHead, sizeof(LIST_ENTRY32), PAGE_READWRITE, &dwOld2);
			WriteProcessMemory(hTargetProc, pVEHHead, &VEHHead.Flink, sizeof(DWORD), nullptr);
			VirtualProtectEx(hTargetProc, pVEHHead, sizeof(LIST_ENTRY32), dwOld1, &dwOld2);

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

		Sleep(10);
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

#endif