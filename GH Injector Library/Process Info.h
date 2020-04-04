#pragma once

#include "Import Handler.h"

//Wrapper class which relies on information from NtQuerySystemInformation and NtQueryInformationProcess

//Used to enumerate threads, retrieve PEBs, etc...

//Honestly, too lazy to document

#define NT_RET_OFFSET_64 0x14
#define NT_RET_OFFSET_86 0x0C

#define TEB_SAMETEBFLAGS_64 0x17EE
#define TEB_SAMETEBFLAGS_86 0xFCA

#ifdef _WIN64
#define NT_RET_OFFSET NT_RET_OFFSET_64
#define TEB_SAMETEBFLAGS TEB_SAMETEBFLAGS_64
#else
#define NT_RET_OFFSET NT_RET_OFFSET_86
#define TEB_SAMETEBFLAGS TEB_SAMETEBFLAGS_86
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

	UINT_PTR m_WaitFunctionReturnAddress[6] = { 0 };

#ifdef _WIN64
	DWORD m_WaitFunctionReturnAddress_WOW64[6] = { 0 };
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

	DWORD GetPID();

	bool IsNative();

	void * GetEntrypoint();

	DWORD GetTID();
	DWORD GetThreadId();
	bool GetThreadState(THREAD_STATE & state, KWAIT_REASON & reason);
	bool GetThreadStartAddress(void *& start_address);
	bool GetThreadStartAddress_WOW64(void *& start_address);
	bool IsThreadInAlertableState();
	bool IsThreadWorkerThread();

	const SYSTEM_PROCESS_INFORMATION	* GetProcessInfo();
	const SYSTEM_THREAD_INFORMATION		* GetThreadInfo();

#ifdef _WIN64

	PEB32					* GetPEB_WOW64();
	LDR_DATA_TABLE_ENTRY32	* GetLdrEntry_WOW64(HINSTANCE hMod);
	bool IsThreadInAlertableState_WOW64();

#endif
};