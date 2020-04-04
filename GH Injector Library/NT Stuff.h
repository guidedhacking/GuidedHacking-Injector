#pragma once

#ifndef _WIN32
#error Rly?
#endif

#include "pch.h"

#pragma region nt defines

#ifndef NT_FAIL
	#define NT_FAIL(status) (status < 0)
#endif

#ifndef NT_SUCCESS
	#define NT_SUCCESS(status) (status >= 0)
#endif

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED	0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH  0x00000002
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER	0x00000004

#define STATUS_UNSUCCESSFUL			0xC0000001
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

typedef LONG KPRIORITY;

#pragma endregion

#pragma region enums

typedef enum class _PROCESSINFOCLASS
{
	ProcessBasicInformation		= 0,
	ProcessSessionInformation	= 24,
	ProcessWow64Information		= 26
} PROCESSINFOCLASS;

typedef enum class _SYSTEM_INFORMATION_CLASS
{
	SystemProcessInformation	= 5,
	SystemHandleInformation		= 16
} SYSTEM_INFORMATION_CLASS;

typedef enum class _THREADINFOCLASS
{
	ThreadBasicInformation			= 0,
	ThreadQuerySetWin32StartAddress = 9
} THREADINFOCLASS;

typedef enum class _THREAD_STATE
{
    Running = 0x02,
    Waiting = 0x05
} THREAD_STATE;

typedef enum class _KWAIT_REASON
{
	WrQueue	= 0x0F
} KWAIT_REASON;

typedef enum class _OBEJECT_TYPE_NUMBER : BYTE
{
	Process = 0x07
} OBJECT_TYPE_NUMBER;

#pragma endregion

#pragma region structs

typedef struct _UNICODE_STRING
{
	WORD		Length;
	WORD		MaxLength;
	wchar_t *	szBuffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY		InLoadOrderLinks;
	LIST_ENTRY		InMemoryOrderLinks;
	union
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};

	PVOID			DllBase;
	PVOID			EntryPoint;
	ULONG			SizeOfImage;

	UNICODE_STRING	FullDllName;
	UNICODE_STRING	BaseDllName;

	ULONG			Flags;
	WORD			LoadCount;
	WORD			TlsIndex;

	LIST_ENTRY		HashLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA
{
	ULONG		Length;
	BYTE		Initialized;
	HANDLE		SsHandle;
	LIST_ENTRY	InLoadOrderModuleListHead;
	LIST_ENTRY	InMemoryOrderModuleListHead;
	LIST_ENTRY	InInitializationOrderModuleListHead;
	void *		EntryInProgress;
	BYTE		ShutdownInProgress;
	HANDLE		ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB
{
	void * Reserved[3];
	PEB_LDR_DATA * Ldr;
} PEB, *PPEB;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _PROCESS_BASIC_INFORMATION
{
	NTSTATUS	ExitStatus;
	PEB *		pPEB;
	ULONG_PTR	AffinityMask;
	LONG		BasePriority;
	HANDLE		UniqueProcessId;
	HANDLE		InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef struct _PROCESS_SESSION_INFORMATION
{
	ULONG SessionId;
} PROCESS_SESSION_INFORMATION, *PPROCESS_SESSION_INFORMATION;

typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS                ExitStatus;
	PVOID                   TebBaseAddress;
	CLIENT_ID               ClientId;
	KAFFINITY               AffinityMask;
	KPRIORITY               Priority;
	KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	WORD UniqueProcessId;
	WORD CreateBackTraceIndex;
	BYTE ObjectTypeIndex;
	BYTE HandleAttributes;
	WORD HandleValue;
	void * Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER	KernelTime;
	LARGE_INTEGER	UserTime;
	LARGE_INTEGER	CreateTime;
	ULONG			WaitTime;
	PVOID			StartAddress;
	CLIENT_ID		ClientId;
	KPRIORITY		Priority;
	LONG			BasePriority;
	ULONG			ContextSwitches;
	THREAD_STATE	ThreadState;
	KWAIT_REASON	WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG			NextEntryOffset;
	ULONG			NumberOfThreads;
	LARGE_INTEGER	WorkingSetPrivateSize;
	ULONG			HardFaultCount;
	ULONG			NumberOfThreadsHighWatermark;
	ULONGLONG		CycleTime;
	LARGE_INTEGER	CreateTime;
	LARGE_INTEGER	UserTime;
	LARGE_INTEGER	KernelTime;
	UNICODE_STRING	ImageName;
	KPRIORITY		BasePriority;
	HANDLE			UniqueProcessId;
	HANDLE			InheritedFromUniqueProcessId;
	ULONG			HandleCount;
	ULONG			SessionId;
	ULONG_PTR		UniqueProcessKey;
	SIZE_T			PeakVirtualSize;
	SIZE_T			VirtualSize;
	ULONG			PageFaultCount;
	SIZE_T 			PeakWorkingSetSize;
	SIZE_T			WorkingSetSize;
	SIZE_T			QuotaPeakPagedPoolUsage;
	SIZE_T 			QuotaPagedPoolUsage;
	SIZE_T 			QuotaPeakNonPagedPoolUsage;
	SIZE_T 			QuotaNonPagedPoolUsage;
	SIZE_T 			PagefileUsage;
	SIZE_T 			PeakPagefileUsage;
	SIZE_T 			PrivatePageCount;
	LARGE_INTEGER	ReadOperationCount;
	LARGE_INTEGER	WriteOperationCount;
	LARGE_INTEGER	OtherOperationCount;
	LARGE_INTEGER 	ReadTransferCount;
	LARGE_INTEGER	WriteTransferCount;
	LARGE_INTEGER	OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef union _LDRP_PATH_SEARCH_OPTIONS
{
	ULONG32 Flags;

	struct
	{
		ULONG32 Unknown;
	};
} LDRP_PATH_SEARCH_OPTIONS, *PLDRP_PATH_SEARCH_OPTIONS;

typedef struct _LDRP_PATH_SEARCH_CONTEXT
{
	UNICODE_STRING				DllSearchPath;
	BOOLEAN						AllocatedOnLdrpHeap;
	LDRP_PATH_SEARCH_OPTIONS	SearchOptions;
	UNICODE_STRING				OriginalFullDllName;
} LDRP_PATH_SEARCH_CONTEXT, *PLDRP_PATH_SEARCH_CONTEXT;

#ifdef _WIN64

typedef struct _UNICODE_STRING32
{
	WORD	Length;
	WORD	MaxLength;
	DWORD	szBuffer;
} UNICODE_STRING32, *PUNICODE_STRING32;

typedef struct _LDRP_PATH_SEARCH_CONTEXT32
{
	UNICODE_STRING32			DllSearchPath;
	BOOLEAN						AllocatedOnLdrpHeap;
	LDRP_PATH_SEARCH_OPTIONS	SearchOptions;
	UNICODE_STRING32			OriginalFullDllName;
} LDRP_PATH_SEARCH_CONTEXT32, *PLDRP_PATH_SEARCH_CONTEXT32;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32		InLoadOrderLinks;
	LIST_ENTRY32		InMemoryOrderLinks;
	LIST_ENTRY32		InInitializationOrderLinks;
	DWORD				DllBase;
	DWORD				EntryPoint;
	ULONG				SizeOfImage;
	UNICODE_STRING32	FullDllName;
	UNICODE_STRING32	BaseDllName;
	ULONG				Flags;
	WORD				LoadCount;
	WORD				TlsIndex;
	union
	{
		LIST_ENTRY32 HashLinks;
		struct
		{
			ULONG SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		ULONG LoadedImports;
	};
	ULONG EntryPointActivationContext;
	ULONG PatchInformation;
	LIST_ENTRY32 ForwarderLinks;
	LIST_ENTRY32 ServiceTagLinks;
	LIST_ENTRY32 StaticLinks;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

typedef struct _PEB_LDR_DATA32
{
	ULONG			Length;
	BYTE			Initialized;
	DWORD			SsHandle;
	LIST_ENTRY32	InLoadOrderModuleListHead;
	LIST_ENTRY32	InMemoryOrderModuleListHead;
	LIST_ENTRY32	InInitializationOrderModuleListHead;
	DWORD			EntryInProgress;
	BYTE			ShutdownInProgress;
	DWORD			ShutdownThreadId;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

typedef struct _PEB32
{
	DWORD Reserved[3];
	DWORD Ldr;
} PEB32, *PPEB32;

#endif

#pragma endregion

#pragma region function prototypes

using f_NtCreateThreadEx = NTSTATUS (__stdcall*)	
(
	HANDLE		*	pHandle, 
	ACCESS_MASK		DesiredAccess, 
	void		*	pAttr, 
	HANDLE			hTargetProc, 
	void		*	pFunc, 
	void		*	pArg,
	ULONG			Flags, 
	SIZE_T			ZeroBits, 
	SIZE_T			StackSize, 
	SIZE_T			MaxStackSize, 
	void		*	pAttrListOut
);

using f_LdrLoadDll = NTSTATUS (__stdcall*)	
(
	wchar_t			*	szOptPath, 
	ULONG				ulFlags, 
	UNICODE_STRING	*	pModuleFileName, 
	HANDLE			*	pOut
);

using f_LdrpLoadDll = NTSTATUS (__fastcall*)
(
	UNICODE_STRING				*	dll_path, 
	LDRP_PATH_SEARCH_CONTEXT	*	search_path,
	ULONG32							Flags,
	LDR_DATA_TABLE_ENTRY		**	ldr_out
);

using f_RtlInsertInvertedFunctionTable = BOOL (__fastcall*)
(
	void	*	hDll,
	DWORD		SizeOfImage
);

using f_NtQueryInformationProcess = NTSTATUS (__stdcall*)
(
	HANDLE					hTargetProc, 
	PROCESSINFOCLASS		PIC, 
	void				*	pBuffer, 
	ULONG					BufferSize, 
	ULONG				*	SizeOut
);

using f_NtQuerySystemInformation = NTSTATUS	(__stdcall*)
(
	SYSTEM_INFORMATION_CLASS		SIC, 
	void						*	pBuffer, 
	ULONG							BufferSize, 
	ULONG						*	SizeOut
);

using f_NtQueryInformationThread = NTSTATUS (__stdcall*)
(
	HANDLE				hThread, 
	THREADINFOCLASS		TIC, 
	void			*	pBuffer, 
	ULONG				BufferSize, 
	ULONG			*	SizeOut
);

using f_RtlQueueApcWow64Thread = NTSTATUS (__stdcall*)
(
	HANDLE		hThread, 
	void	*	pRoutine, 
	void	*	pArg1, 
	void	*	pArg2, 
	void	*	pArg3
);

#pragma endregion

#define NT_FUNC(Function) inline f_##Function Function = nullptr;
#define LOAD_NT_FUNC(Function, Library, FunctionName) NT::Function = reinterpret_cast<f_##Function>(GetProcAddress(Library, FunctionName))

namespace NT
{
	NT_FUNC(NtCreateThreadEx);
	NT_FUNC(LdrLoadDll);
	NT_FUNC(LdrpLoadDll);
	NT_FUNC(RtlInsertInvertedFunctionTable);
	NT_FUNC(NtQueryInformationProcess);
	NT_FUNC(NtQuerySystemInformation);
	NT_FUNC(NtQueryInformationThread);

#ifdef _WIN64
	NT_FUNC(RtlQueueApcWow64Thread);
#endif
}