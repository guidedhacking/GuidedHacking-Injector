#include "pch.h"

#include "Process Info.h"

#define NEXT_SYSTEM_PROCESS_ENTRY(pCurrent) ReCa<SYSTEM_PROCESS_INFORMATION *>(ReCa<BYTE *>(pCurrent) + pCurrent->NextEntryOffset)

ProcessInfo::ProcessInfo()
{
	HINSTANCE hNTDLL = GetModuleHandleW(L"ntdll.dll");
	if (!hNTDLL)
	{
		return;
	}

	LOG(3, "Creating ProcessInfo\n");

	m_pNtQueryInformationProcess	= ReCa<f_NtQueryInformationProcess>	(GetProcAddress(hNTDLL, "NtQueryInformationProcess"));
	m_pNtQuerySystemInformation		= ReCa<f_NtQuerySystemInformation>	(GetProcAddress(hNTDLL, "NtQuerySystemInformation"));
	m_pNtQueryInformationThread		= ReCa<f_NtQueryInformationThread>	(GetProcAddress(hNTDLL, "NtQueryInformationThread"));

	if (!m_pNtQueryInformationProcess || !m_pNtQuerySystemInformation || !m_pNtQueryInformationThread)
	{
		return;
	}

	m_BufferSize	= 0x10000;
	m_pFirstProcess = nullptr;

	ULONG nt_ret_offset = 0;

#ifdef _WIN64
	if (GetOSBuildVersion() <= g_Win10_1507)
	{
		nt_ret_offset = NT_RET_OFFSET_64_WIN7;
	}
	else
	{
		nt_ret_offset = NT_RET_OFFSET_64_WIN10_1511;
	}
#else
	if (GetOSVersion() == g_Win7)
	{
		nt_ret_offset = NT_RET_OFFSET_86_WIN7;
	}
	else
	{
		nt_ret_offset = NT_RET_OFFSET_86_WIN8;
	}
#endif

	m_WaitFunctionReturnAddress[0] = ReCa<UINT_PTR>(GetProcAddress(hNTDLL, "NtDelayExecution"				)) + nt_ret_offset;
	m_WaitFunctionReturnAddress[1] = ReCa<UINT_PTR>(GetProcAddress(hNTDLL, "NtWaitForSingleObject"			)) + nt_ret_offset;
	m_WaitFunctionReturnAddress[2] = ReCa<UINT_PTR>(GetProcAddress(hNTDLL, "NtWaitForMultipleObjects"		)) + nt_ret_offset;
	m_WaitFunctionReturnAddress[3] = ReCa<UINT_PTR>(GetProcAddress(hNTDLL, "NtSignalAndWaitForSingleObject"	)) + nt_ret_offset;

	if (GetOSBuildVersion() >= g_Win10_1607)
	{
		m_hWin32U = LoadLibraryW(L"win32u.dll");
		if (m_hWin32U)
		{
			m_WaitFunctionReturnAddress[4] = ReCa<UINT_PTR>(GetProcAddress(m_hWin32U, "NtUserMsgWaitForMultipleObjectsEx")) + nt_ret_offset;
		}
	}

	LOG(3, "ProcessInfo initialized\n");
}

ProcessInfo::~ProcessInfo()
{
	if (m_hWin32U)
	{
		FreeLibrary(m_hWin32U);
	}

	if (m_pFirstProcess)
	{
		delete[] m_pFirstProcess;
	}
}

bool ProcessInfo::SetProcess(HANDLE hTargetProc)
{
	DWORD dwHandleInfo = 0;
	if (!hTargetProc || hTargetProc == INVALID_HANDLE_VALUE || !GetHandleInformation(hTargetProc, &dwHandleInfo))
	{
		return false;
	}

	if (!m_pFirstProcess)
	{
		if (!RefreshInformation())
		{
			return false;
		}
	}

	m_hCurrentProcess = hTargetProc;

#ifdef _WIN64
	m_IsWow64 = IsNative() ? false : true;
#endif

	ULONG_PTR PID = GetProcessId(m_hCurrentProcess);

	while (NEXT_SYSTEM_PROCESS_ENTRY(m_pCurrentProcess) != m_pCurrentProcess)
	{
		if (m_pCurrentProcess->UniqueProcessId == ReCa<void *>(PID))
		{
			break;
		}

		m_pCurrentProcess = NEXT_SYSTEM_PROCESS_ENTRY(m_pCurrentProcess);
	}

	if (m_pCurrentProcess->UniqueProcessId != ReCa<void *>(PID))
	{
		m_pCurrentProcess = m_pFirstProcess;
		return false;
	}

	m_CurrentThreadIndex = 0;
	m_pCurrentThread = &m_pCurrentProcess->Threads[0];

	return true;
}

bool ProcessInfo::SetThread(DWORD TID)
{
	if (!m_pFirstProcess)
	{
		return false;
	}

	m_pCurrentThread = nullptr;

	for (UINT i = 0; i != m_pCurrentProcess->NumberOfThreads; ++i)
	{
		if (m_pCurrentProcess->Threads[i].ClientId.UniqueThread == ReCa<void *>(ULONG_PTR(TID)))
		{
			m_CurrentThreadIndex = i;
			m_pCurrentThread = &m_pCurrentProcess->Threads[i];

			break;
		}
	}
	
	if (m_pCurrentThread == nullptr)
	{
		m_CurrentThreadIndex = 0;
		m_pCurrentThread = &m_pCurrentProcess->Threads[0];

		return false;
	}

	return true;
}

bool ProcessInfo::FirstThread()
{
	if (!m_pFirstProcess)
	{
		return false;
	}

	m_CurrentThreadIndex = 0;
	m_pCurrentThread = &m_pCurrentProcess->Threads[0];

	return true;
}

bool ProcessInfo::NextThread()
{
	if (!m_pFirstProcess)
	{
		return false;
	}

	if (m_CurrentThreadIndex == m_pCurrentProcess->NumberOfThreads - 1)
	{
		return false;
	}

	m_pCurrentThread = &m_pCurrentProcess->Threads[++m_CurrentThreadIndex];

	return true;
}

bool ProcessInfo::RefreshInformation()
{
	if (!m_pFirstProcess)
	{
		m_pFirstProcess = ReCa<SYSTEM_PROCESS_INFORMATION *>(new(std::nothrow) BYTE[m_BufferSize]());
		if (!m_pFirstProcess)
		{
			return false;
		}
	}
	else
	{
		delete[] m_pFirstProcess;
		m_pFirstProcess = nullptr;

		return RefreshInformation();
	}

	ULONG size_out = 0;
	NTSTATUS ntRet = m_pNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, m_pFirstProcess, m_BufferSize, &size_out);

	while (ntRet == STATUS_INFO_LENGTH_MISMATCH)
	{
		delete[] m_pFirstProcess;

		m_BufferSize	= size_out + 0x1000;
		m_pFirstProcess = ReCa<SYSTEM_PROCESS_INFORMATION *>(new(std::nothrow) BYTE[m_BufferSize]);
		if (!m_pFirstProcess)
		{
			return false;
		}

		ntRet = m_pNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, m_pFirstProcess, m_BufferSize, &size_out);
	}

	if (NT_FAIL(ntRet))
	{
		delete[] m_pFirstProcess;
		m_pFirstProcess = nullptr;

		return false;
	}

	m_pCurrentProcess	= m_pFirstProcess;
	m_pCurrentThread	= &m_pCurrentProcess->Threads[0];

	return true;
}

PEB * ProcessInfo::GetPEB()
{
	return GetPEB_Native();
}

LDR_DATA_TABLE_ENTRY * ProcessInfo::GetLdrEntry(HINSTANCE hMod)
{
	return GetLdrEntry_Native(hMod);
}

PEB * ProcessInfo::GetPEB_Native()
{
	if (!m_pFirstProcess)
	{
		return nullptr;
	}

	PROCESS_BASIC_INFORMATION PBI{ 0 };
	ULONG size_out = 0;
	NTSTATUS ntRet = m_pNtQueryInformationProcess(m_hCurrentProcess, PROCESSINFOCLASS::ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &size_out);

	if (NT_FAIL(ntRet))
	{
		return nullptr;
	}

	return PBI.pPEB;
}

LDR_DATA_TABLE_ENTRY * ProcessInfo::GetLdrEntry_Native(HINSTANCE hMod)
{
	if (!m_pFirstProcess)
	{
		return nullptr;
	}

	PEB * ppeb = GetPEB();
	if (!ppeb)
	{
		return nullptr;
	}

	PEB	peb{ 0 };
	if (!ReadProcessMemory(m_hCurrentProcess, ppeb, &peb, sizeof(peb), nullptr))
	{
		return nullptr;
	}

	PEB_LDR_DATA ldrdata{ 0 };
	if (!ReadProcessMemory(m_hCurrentProcess, peb.Ldr, &ldrdata, sizeof(ldrdata), nullptr))
	{
		return nullptr;
	}

	LIST_ENTRY * pCurrentEntry = ldrdata.InLoadOrderModuleListHead.Flink;
	LIST_ENTRY * pLastEntry = ldrdata.InLoadOrderModuleListHead.Blink;

	while (true)
	{
		LDR_DATA_TABLE_ENTRY CurrentEntry{ };
		ReadProcessMemory(m_hCurrentProcess, pCurrentEntry, &CurrentEntry, sizeof(CurrentEntry), nullptr);

		if (CurrentEntry.DllBase == hMod)
		{
			return ReCa<LDR_DATA_TABLE_ENTRY *>(pCurrentEntry);
		}
		else if (pCurrentEntry == pLastEntry)
		{
			break;
		}

		pCurrentEntry = CurrentEntry.InLoadOrderLinks.Flink;
	}

	return nullptr;
}

void * ProcessInfo::GetEntrypoint()
{
	if (!m_pFirstProcess)
	{
		return nullptr;
	}

	PEB * ppeb = GetPEB();
	if (!ppeb)
	{
		return nullptr;
	}

	PEB	peb{ };
	if (!ReadProcessMemory(m_hCurrentProcess, ppeb, &peb, sizeof(peb), nullptr))
	{
		return nullptr;
	}

	PEB_LDR_DATA ldrdata{ };
	if (!ReadProcessMemory(m_hCurrentProcess, peb.Ldr, &ldrdata, sizeof(ldrdata), nullptr))
	{
		return nullptr;
	}

	LIST_ENTRY * pCurrentEntry	= ldrdata.InLoadOrderModuleListHead.Flink;
	LIST_ENTRY * pLastEntry		= ldrdata.InLoadOrderModuleListHead.Blink;

	wchar_t NameBuffer[MAX_PATH]{ 0 };
	while (true)
	{
		LDR_DATA_TABLE_ENTRY CurrentEntry{ };
		if (ReadProcessMemory(m_hCurrentProcess, pCurrentEntry, &CurrentEntry, sizeof(CurrentEntry), nullptr))
		{
			if (CurrentEntry.BaseDllName.Length < sizeof(NameBuffer) && CurrentEntry.BaseDllName.szBuffer)
			{
				if (ReadProcessMemory(m_hCurrentProcess, CurrentEntry.BaseDllName.szBuffer, NameBuffer, CurrentEntry.BaseDllName.Length, nullptr))
				{
					std::wstring Name = NameBuffer + CurrentEntry.BaseDllName.Length / sizeof(wchar_t) - 3; //std::wstring::ends_with doesn't support case insensitive comparisons...
					if (lstrcmpiW(Name.c_str(), L"exe") == 0)
					{
						return MPTR(CurrentEntry.EntryPoint);
					}
				}
			}			
		}

		if (pCurrentEntry == pLastEntry)
		{
			break;
		}

		pCurrentEntry = CurrentEntry.InLoadOrderLinks.Flink;
	}

	return nullptr;
}

DWORD ProcessInfo::GetPID()
{
	return GetProcessId(m_hCurrentProcess);
}

DWORD ProcessInfo::GetSessionID()
{
	if (m_pFirstProcess)
	{
		return m_pCurrentProcess->SessionId;
	}

	return SESSION_ID_INVALID;
}

bool ProcessInfo::IsNative()
{
	BOOL bOut = FALSE;
	IsWow64Process(m_hCurrentProcess, &bOut);
	return (bOut == FALSE);
}

bool ProcessInfo::IsProtected()
{
	BYTE info = 0;

	if (NT_FAIL(m_pNtQueryInformationProcess(m_hCurrentProcess, PROCESSINFOCLASS::ProcessProtectionInformation, &info, sizeof(info), nullptr)))
	{
		return true;
	}

	return (info != 0);
}

DWORD ProcessInfo::GetTID()
{
	if (!m_pCurrentThread)
	{
		return 0;
	}

	return DWORD(ReCa<ULONG_PTR>(m_pCurrentThread->ClientId.UniqueThread) & 0xFFFFFFFF);
}

DWORD ProcessInfo::GetThreadId()
{
	if (!m_pCurrentThread)
	{
		return 0;
	}

	return DWORD(ReCa<ULONG_PTR>(m_pCurrentThread->ClientId.UniqueThread) & 0xFFFFFFFF);
}

//Stolen from here:
//https://github.com/changeofpace/Remote-Process-Cookie-for-Windows-7/blob/master/Remote%20Process%20Cookie%20for%20Windows%207/main.cpp
//Thanks, changeofpace!
ULONG ProcessInfo::GetProcessCookie()
{
	if (!m_pFirstProcess)
	{
		return 0;
	}

	ULONG cookie = 0;
	if (GetOSVersion() == g_Win7)
	{
#ifdef _WIN64
		if (m_IsWow64)
		{
			DWORD ctrl1 = WOW64::UnhandledExceptionFilter_WOW64;
			DWORD ctrl2 = WOW64::DefaultHandler_WOW64;

			DWORD ptr1 = 0;
			DWORD ptr2 = 0;

			BOOL bRet = TRUE;
			bRet &= ReadProcessMemory(m_hCurrentProcess, MPTR(WOW64::RtlpUnhandledExceptionFilter_WOW64), &ptr1, sizeof(ptr1), nullptr);
			bRet &= ReadProcessMemory(m_hCurrentProcess, MPTR(WOW64::SingleHandler_WOW64), &ptr2, sizeof(ptr2), nullptr);

			if (!bRet)
			{
				return 0;
			}

			for (int i = 0; i < 0x20; ++i)
			{
				ULONG guess = _rotr(ptr1, i) ^ ctrl1;
				DWORD test	= _rotl(ptr2, guess & 0x1F) ^ guess;

				if (test == ctrl2)
				{
					cookie = guess;
					break;
				}
			}
		}
		else
		{
			ULONG_PTR ctrl1 = ReCa<ULONG_PTR>(NATIVE::UnhandledExceptionFilter);
			ULONG_PTR ctrl2 = ReCa<ULONG_PTR>(NATIVE::DefaultHandler);
		
			ULONG_PTR ptr1 = 0;
			ULONG_PTR ptr2 = 0;

			BOOL bRet = TRUE;
			bRet &= ReadProcessMemory(m_hCurrentProcess, NATIVE::RtlpUnhandledExceptionFilter, &ptr1, sizeof(ptr1), nullptr);
			bRet &= ReadProcessMemory(m_hCurrentProcess, NATIVE::SingleHandler, &ptr2, sizeof(ptr2), nullptr);

			if (!bRet)
			{
				return 0;
			}

			for (int i = 0; i < 0x40; ++i)
			{
				ULONG guess = ULONG(_rotr64(ptr1, i) ^ ctrl1);
				ULONG_PTR test = _rotl64(ptr2, guess & 0x3F) ^ guess;
				if (test == ctrl2)
				{
					cookie = guess;
					break;
				}
			}
		}
#else
		ULONG_PTR ctrl1 = ReCa<ULONG_PTR>(NATIVE::UnhandledExceptionFilter);
		ULONG_PTR ctrl2 = ReCa<ULONG_PTR>(NATIVE::DefaultHandler);

		ULONG_PTR ptr1 = 0;
		ULONG_PTR ptr2 = 0;

		BOOL bRet = TRUE;
		bRet &= ReadProcessMemory(m_hCurrentProcess, NATIVE::RtlpUnhandledExceptionFilter, &ptr1, sizeof(ptr1), nullptr);
		bRet &= ReadProcessMemory(m_hCurrentProcess, NATIVE::SingleHandler, &ptr2, sizeof(ptr2), nullptr);

		if (!bRet)
		{
			return 0;
		}

		for (int i = 0; i < 0x20; ++i)
		{
			ULONG guess		= ULONG(_rotr(ptr1, i) ^ ctrl1);
			ULONG_PTR test	= _rotl(ptr2, guess & 0x1F) ^ guess;

			if (test == ctrl2)
			{
				cookie = guess;
				break;
			}
		}
#endif
	}
	else
	{
		m_pNtQueryInformationProcess(m_hCurrentProcess, PROCESSINFOCLASS::ProcessCookie, &cookie, sizeof(cookie), nullptr);
	}

	return cookie;
}

bool ProcessInfo::GetThreadState(KTHREAD_STATE & state, KWAIT_REASON & reason)
{
	if (!m_pCurrentThread)
	{
		return 0;
	}

	state	= m_pCurrentThread->ThreadState;
	reason	= m_pCurrentThread->WaitReason;

	return true;
}

bool ProcessInfo::GetThreadStartAddress(void *& start_address)
{
	if (!m_pCurrentThread)
	{
		return false;
	}

	start_address = m_pCurrentThread->StartAddress;

	return true;
}

void * ProcessInfo::GetTEB()
{
	if (!m_pCurrentThread)
	{
		return nullptr;
	}

	HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, FALSE, MDWD(m_pCurrentThread->ClientId.UniqueThread));
	if (!hThread)
	{
		return nullptr;
	}

	THREAD_BASIC_INFORMATION tbi{ 0 };
	auto ntRet = m_pNtQueryInformationThread(hThread, THREADINFOCLASS::ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);

	CloseHandle(hThread);

	if (NT_FAIL(ntRet))
	{
		return nullptr;
	}

	return tbi.TebBaseAddress;
}

bool ProcessInfo::IsThreadInAlertableState()
{
	if (!m_pCurrentThread)
	{
		return false;
	}

	HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, MDWD(m_pCurrentThread->ClientId.UniqueThread));
	if (!hThread)
	{
		return false;
	}

	CONTEXT ctx{ 0 };
	ctx.ContextFlags = CONTEXT_ALL;

	if (!GetThreadContext(hThread, &ctx))
	{
		CloseHandle(hThread);

		return false;
	}

	CloseHandle(hThread);

#ifdef _WIN64

	if (!ctx.Rip || !ctx.Rsp)
	{
		return false;
	}

	if (ctx.Rip == m_WaitFunctionReturnAddress[0]) //NtDelayExecution
	{
		if (GetOSVersion() == g_Win7)
		{
			return (ctx.Rdi == TRUE);
		}
		else if (GetOSBuildVersion() <= g_Win10_1709)
		{
			return (ctx.Rbx == TRUE);
		}
		else
		{
			return (ctx.Rcx == TRUE);
		}
	}
	else if (ctx.Rip == m_WaitFunctionReturnAddress[1]) //NtWaitForSingleObject
	{
		return (ctx.Rbx == TRUE);
	}
	else if (ctx.Rip == m_WaitFunctionReturnAddress[2] || ctx.Rip == m_WaitFunctionReturnAddress[3]) //NtWaitForMultipleObjects & NtSignalAndWaitForSingleObject
	{
		return (ctx.Rsi == TRUE);
	}
	else if (ctx.Rip == m_WaitFunctionReturnAddress[4]) //NtUserMsgWaitForMultipleObjectsEx
	{
		DWORD Flags = FALSE;
		if (ReadProcessMemory(m_hCurrentProcess, ReCa<void *>(ctx.Rsp + 0x28), &Flags, sizeof(Flags), nullptr))
		{
			return ((Flags & MWMO_ALERTABLE) != 0);
		}
	}

#else

	if (!ctx.Eip || !ctx.Esp)
	{
		return false;
	}

	DWORD stack_buffer[6] = { 0 };
	if (!ReadProcessMemory(m_hCurrentProcess, ReCa<void *>(ctx.Esp), stack_buffer, sizeof(stack_buffer), nullptr))
	{
		return false;
	}

	if (ctx.Eip == m_WaitFunctionReturnAddress[0]) //NtDelayExecution
	{
		if (GetOSVersion() == g_Win7)
		{
			return (stack_buffer[2] == TRUE);
		}
		else
		{
			return (stack_buffer[1] == TRUE);
		}
	}
	else if (ctx.Eip == m_WaitFunctionReturnAddress[1]) //NtWaitForSingleObject
	{
		if (GetOSVersion() == g_Win7)
		{
			return (stack_buffer[3] == TRUE);
		}
		else
		{
			return (stack_buffer[2] == TRUE);
		}
	}
	else if (ctx.Eip == m_WaitFunctionReturnAddress[2]) //NtWaitForMultipleObjects
	{
		if (GetOSVersion() == g_Win7)
		{
			return (stack_buffer[5] == TRUE);
		}
		else
		{
			return (stack_buffer[4] == TRUE);
		}
	}
	else if (ctx.Eip == m_WaitFunctionReturnAddress[3]) //NtSignalAndWaitForSingleObject
	{
		if (GetOSVersion() == g_Win7)
		{
			return (stack_buffer[4] == TRUE);
		}
		else
		{
			return (stack_buffer[3] == TRUE);
		}
	}
	else if (ctx.Eip == m_WaitFunctionReturnAddress[4]) //NtUserMsgWaitForMultipleObjectsEx
	{
		return ((stack_buffer[5] & MWMO_ALERTABLE) != 0);
	}

#endif

	return false;
}

bool ProcessInfo::IsThreadWorkerThread()
{
	if (GetOSVersion() < g_Win10)
	{
		//TEB_SAMETEB_FLAGS::LoaderWorker is Win10+ only

		return false;
	}

	if (!m_pCurrentThread)
	{
		return false;
	}

	BYTE * teb = ReCa<BYTE *>(GetTEB());
	if (!teb)
	{
		return false;
	}

	USHORT TebInfo = NULL;
	if (ReadProcessMemory(m_hCurrentProcess, teb + TEB_SameTebFlags, &TebInfo, sizeof(TebInfo), nullptr))
	{
		return ((TebInfo & TEB_SAMETEB_FLAGS_LoaderWorker) != 0);
	}

	return false;
}

const SYSTEM_PROCESS_INFORMATION * ProcessInfo::GetProcessInfo()
{
	return m_pFirstProcess ? m_pCurrentProcess : nullptr;
}

const SYSTEM_THREAD_INFORMATION * ProcessInfo::GetThreadInfo()
{
	return m_pFirstProcess ? m_pCurrentThread : nullptr;
}

#ifdef _WIN64

PEB_32 * ProcessInfo::GetPEB_WOW64()
{
	if (!m_pFirstProcess || !m_IsWow64)
	{
		return 0;
	}

	ULONG_PTR pPEB;
	ULONG size_out = 0;
	NTSTATUS ntRet = m_pNtQueryInformationProcess(m_hCurrentProcess, PROCESSINFOCLASS::ProcessWow64Information, &pPEB, sizeof(pPEB), &size_out);

	if (NT_FAIL(ntRet))
	{ 
		return nullptr;
	}

	return ReCa<PEB_32 *>(pPEB);
}

LDR_DATA_TABLE_ENTRY_32 * ProcessInfo::GetLdrEntry_WOW64(HINSTANCE hMod)
{
	if (!m_pFirstProcess || !m_IsWow64)
	{
		return nullptr;
	}
	
	PEB_32 * ppeb = GetPEB_WOW64();
	if (!ppeb)
	{
		return nullptr;
	}

	PEB_32 peb{ 0 };
	if (!ReadProcessMemory(m_hCurrentProcess, ppeb, &peb, sizeof(peb), nullptr))
	{
		return nullptr;
	}
	
	PEB_LDR_DATA_32 ldrdata{ 0 };
	if (!ReadProcessMemory(m_hCurrentProcess, MPTR(peb.Ldr), &ldrdata, sizeof(ldrdata), nullptr))
	{
		return nullptr;
	}
		
	LIST_ENTRY32 * pCurrentEntry	= ReCa<LIST_ENTRY32 *>((ULONG_PTR)ldrdata.InLoadOrderModuleListHead.Flink);
	LIST_ENTRY32 * pLastEntry		= ReCa<LIST_ENTRY32 *>((ULONG_PTR)ldrdata.InLoadOrderModuleListHead.Blink);

	while (true)
	{
		LDR_DATA_TABLE_ENTRY_32 CurrentEntry{ };
		ReadProcessMemory(m_hCurrentProcess, pCurrentEntry, &CurrentEntry, sizeof(CurrentEntry), nullptr);

		if (CurrentEntry.DllBase == MDWD(hMod))
		{
			return ReCa<LDR_DATA_TABLE_ENTRY_32 *>(pCurrentEntry);
		}
		else if (pCurrentEntry == pLastEntry)			
		{
			break;
		}

		pCurrentEntry = ReCa<LIST_ENTRY32 *>((ULONG_PTR)CurrentEntry.InLoadOrderLinks.Flink);
	}

	return nullptr;
}

void * ProcessInfo::GetEntrypoint_WOW64()
{
	if (!m_pFirstProcess)
	{
		return nullptr;
	}

	PEB_32 * ppeb = GetPEB_WOW64();
	if (!ppeb)
	{
		return nullptr;
	}

	PEB_32 peb{ };
	if (!ReadProcessMemory(m_hCurrentProcess, ppeb, &peb, sizeof(peb), nullptr))
	{
		return nullptr;
	}

	PEB_LDR_DATA_32 ldrdata{ };
	if (!ReadProcessMemory(m_hCurrentProcess, MPTR(peb.Ldr), &ldrdata, sizeof(ldrdata), nullptr))
	{
		return nullptr;
	}

	auto * pCurrentEntry	= ReCa<LIST_ENTRY32 *>(MPTR(ldrdata.InLoadOrderModuleListHead.Flink));
	auto * pLastEntry		= ReCa<LIST_ENTRY32 *>(MPTR(ldrdata.InLoadOrderModuleListHead.Blink));

	wchar_t NameBuffer[MAX_PATH]{ 0 };
	while (true)
	{
		LDR_DATA_TABLE_ENTRY_32 CurrentEntry{ };
		if (ReadProcessMemory(m_hCurrentProcess, pCurrentEntry, &CurrentEntry, sizeof(CurrentEntry), nullptr))
		{
			if (CurrentEntry.BaseDllName.Length < sizeof(NameBuffer) && CurrentEntry.BaseDllName.Length > 4 && CurrentEntry.BaseDllName.szBuffer)
			{
				if (ReadProcessMemory(m_hCurrentProcess, MPTR(CurrentEntry.BaseDllName.szBuffer), NameBuffer, CurrentEntry.BaseDllName.Length, nullptr))
				{
					std::wstring Name = NameBuffer + CurrentEntry.BaseDllName.Length / sizeof(wchar_t) - 3; //std::wstring::ends_with doesn't support case insensitive comparisons...
					if (lstrcmpiW(Name.c_str(), L"exe") == 0)
					{
						return MPTR(CurrentEntry.EntryPoint);
					}
				}
			}
		}

		if (pCurrentEntry == pLastEntry)
		{
			break;
		}

		pCurrentEntry = ReCa<LIST_ENTRY32 *>(MPTR(CurrentEntry.InLoadOrderLinks.Flink));
	}

	return nullptr;
}

bool ProcessInfo::GetThreadStartAddress_WOW64(void *& start_address)
{
	if (!m_pCurrentThread || !m_IsWow64)
	{
		return false;
	}

	HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, FALSE, MDWD(m_pCurrentThread->ClientId.UniqueThread));
	if (!hThread)
	{
		return false;
	}

	if (NT_SUCCESS(m_pNtQueryInformationThread(hThread, THREADINFOCLASS::ThreadQuerySetWin32StartAddress, &start_address, sizeof(start_address), nullptr)))
	{
		CloseHandle(hThread);

		return true;
	}

	CloseHandle(hThread);

	return false;
}

bool ProcessInfo::IsThreadInAlertableState_WOW64()
{
	if (!m_pCurrentThread || !m_IsWow64)
	{
		return false;
	}

	if (m_WaitFunctionReturnAddress_WOW64[0] == 0)
	{
		HINSTANCE hNTDLL = GetModuleHandleExW_WOW64(m_hCurrentProcess, L"ntdll.dll");
		if (!hNTDLL)
		{
			return false;
		}
		
		DWORD Address = 0;

		ULONG nt_ret_offset = 0;

		if (GetOSVersion() > g_Win7)
		{
			nt_ret_offset = NT_RET_OFFSET_86_WIN8;
		}
		else
		{
			nt_ret_offset = NT_RET_OFFSET_86_WIN7;
		}

		GetProcAddressEx_WOW64(m_hCurrentProcess, hNTDLL, "NtDelayExecution", Address);
		m_WaitFunctionReturnAddress_WOW64[0] = Address + nt_ret_offset;

		GetProcAddressEx_WOW64(m_hCurrentProcess, hNTDLL, "NtWaitForSingleObject", Address);
		m_WaitFunctionReturnAddress_WOW64[1] = Address + nt_ret_offset;

		GetProcAddressEx_WOW64(m_hCurrentProcess, hNTDLL, "NtWaitForMultipleObjects", Address);
		m_WaitFunctionReturnAddress_WOW64[2] = Address + nt_ret_offset;

		GetProcAddressEx_WOW64(m_hCurrentProcess, hNTDLL, "NtSignalAndWaitForSingleObject", Address);
		m_WaitFunctionReturnAddress_WOW64[3] = Address + nt_ret_offset;

		if (GetOSBuildVersion() >= g_Win10_1607)
		{
			HINSTANCE hWIN32U = GetModuleHandleExW_WOW64(m_hCurrentProcess, L"win32u.dll");
			if (hWIN32U)
			{
				GetProcAddressEx_WOW64(m_hCurrentProcess, hWIN32U, "NtUserMsgWaitForMultipleObjectsEx", Address);
				m_WaitFunctionReturnAddress_WOW64[4] = Address + nt_ret_offset;
			}
		}
	}

	HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, MDWD(m_pCurrentThread->ClientId.UniqueThread));
	if (!hThread)
	{
		return false;
	}

	WOW64_CONTEXT ctx{ 0 };
	ctx.ContextFlags = WOW64_CONTEXT_ALL;

	if (!Wow64GetThreadContext(hThread, &ctx) || !ctx.Eip || !ctx.Esp)
	{
		CloseHandle(hThread);

		return false;
	}
	
	CloseHandle(hThread);
	
	DWORD stack_buffer[6] = { 0 };
	if (!ReadProcessMemory(m_hCurrentProcess, MPTR(ctx.Esp), stack_buffer, sizeof(stack_buffer), nullptr))
	{
		return false;
	}

	if (ctx.Eip == m_WaitFunctionReturnAddress_WOW64[0]) //NtDelayExecution
	{
		if (GetOSVersion() == g_Win7)
		{
			return (stack_buffer[2] == TRUE);
		}
		else
		{
			return (stack_buffer[1] == TRUE);
		}
	}
	else if (ctx.Eip == m_WaitFunctionReturnAddress_WOW64[1]) //NtWaitForSingleObject
	{
		if (GetOSVersion() == g_Win7)
		{
			return (stack_buffer[3] == TRUE);
		}
		else
		{
			return (stack_buffer[2] == TRUE);
		}
	}
	else if (ctx.Eip == m_WaitFunctionReturnAddress_WOW64[2]) //NtWaitForMultipleObjects
	{
		if (GetOSVersion() == g_Win7)
		{
			return (stack_buffer[5] == TRUE);
		}
		else
		{
			return (stack_buffer[4] == TRUE);
		}
	}
	else if (ctx.Eip == m_WaitFunctionReturnAddress_WOW64[3]) //NtSignalAndWaitForSingleObject
	{
		if (GetOSVersion() == g_Win7)
		{
			return (stack_buffer[4] == TRUE);
		}
		else
		{
			return (stack_buffer[3] == TRUE);
		}
	}
	else if (ctx.Eip == m_WaitFunctionReturnAddress_WOW64[4]) //NtUserMsgWaitForMultipleObjectsEx
	{
		return ((stack_buffer[5] & MWMO_ALERTABLE) != 0);
	}
	
	return false;		
}

void * ProcessInfo::GetTEB_WOW64()
{
	if (!m_pCurrentThread || !m_IsWow64)
	{
		return nullptr;
	}
	
	BYTE * ret = ReCa<BYTE *>(GetTEB());
	if (!ret)
	{
		return nullptr;
	}

	if (GetOSVersion() >= g_Win10)
	{
		LONG WowTebOffset = 0;
		if (ReadProcessMemory(m_hCurrentProcess, ret + TEB_WowTebOffset_64, &WowTebOffset, sizeof(WowTebOffset), nullptr))
		{
			//TEB32 = TEB64 + TEB64.WowTebOffset
			return ret + WowTebOffset;
		}
	}
	
	//TEB32 = TEB64 + 0x2000
	return ret + 0x2000;
}

#endif