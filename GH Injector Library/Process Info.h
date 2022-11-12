#pragma once

#include "Import Handler.h"

//Wrapper class which relies on information from NtQuerySystemInformation and NtQueryInformationProcess

//Used to enumerate threads, retrieve PEBs, etc...

//Honestly, too lazy to document

#define NT_RET_OFFSET_64_WIN7		0x0A //Win7 - Win10 1507
#define NT_RET_OFFSET_64_WIN10_1511 0x14 //Win10 1511+

#define NT_RET_OFFSET_86_WIN7 0x15 //Win7 only
#define NT_RET_OFFSET_86_WIN8 0x0C //Win8+

#define TEB_SameTebFlags_64 0x17EE
#define TEB_SameTebFlags_86 0xFCA

#define TEB_WowTebOffset_64 0x180C //Win10+ only

#define TEB_SAMETEB_FLAGS_SkipAttach	0x0008
#define TEB_SAMETEB_FLAGS_LoaderWorker	0x2000

#ifdef _WIN64
#define TEB_SameTebFlags TEB_SameTebFlags_64
#else
#define TEB_SameTebFlags TEB_SameTebFlags_86
#endif

class ProcessInfo
{
	SYSTEM_PROCESS_INFORMATION	* m_pCurrentProcess = nullptr;
	SYSTEM_PROCESS_INFORMATION	* m_pFirstProcess	= nullptr;
	SYSTEM_THREAD_INFORMATION	* m_pCurrentThread	= nullptr;

	ULONG m_BufferSize = 0;

	HANDLE m_hCurrentProcess = nullptr;

	DWORD m_CurrentThreadIndex = 0;

	f_NtQueryInformationProcess m_pNtQueryInformationProcess	= nullptr;
	f_NtQuerySystemInformation	m_pNtQuerySystemInformation		= nullptr;
	f_NtQueryInformationThread	m_pNtQueryInformationThread		= nullptr;

	PEB						* GetPEB_Native();
	LDR_DATA_TABLE_ENTRY	* GetLdrEntry_Native(HINSTANCE hMod);

	UINT_PTR m_WaitFunctionReturnAddress[5] = { 0 };

	HINSTANCE m_hWin32U = NULL;

#ifdef _WIN64
	DWORD	m_WaitFunctionReturnAddress_WOW64[5]	= { 0 };
	bool	m_IsWow64								= false;
#endif

public:

	ProcessInfo();
	~ProcessInfo();

	bool SetProcess(HANDLE hTargetProc);
	bool SetThread(DWORD TID);

	bool FirstThread();
	bool NextThread();

	bool RefreshInformation();

	PEB						* GetPEB();
	LDR_DATA_TABLE_ENTRY	* GetLdrEntry(HINSTANCE hMod);
	void					* GetEntrypoint();

	DWORD GetPID();
	DWORD GetSessionID();

	bool IsNative();
	bool IsProtected();

	DWORD GetTID();
	DWORD GetThreadId();

	DWORD GetProcessCookie();

	bool GetThreadState(KTHREAD_STATE & state, KWAIT_REASON & reason);
	bool GetThreadStartAddress(void *& start_address);
	void * GetTEB();

	bool IsThreadInAlertableState();
	bool IsThreadWorkerThread();

	const SYSTEM_PROCESS_INFORMATION	* GetProcessInfo();
	const SYSTEM_THREAD_INFORMATION		* GetThreadInfo();

#ifdef _WIN64

	PEB_32					* GetPEB_WOW64();
	LDR_DATA_TABLE_ENTRY_32	* GetLdrEntry_WOW64(HINSTANCE hMod);
	void					* GetEntrypoint_WOW64();

	bool GetThreadStartAddress_WOW64(void *& start_address);
	bool IsThreadInAlertableState_WOW64();
	void * GetTEB_WOW64();

#endif
};