#pragma once

#ifndef _WIN32
#error Rly?
#endif

#include "pch.h"

#pragma region nt (un)defines

#ifndef NT_FAIL
	#define NT_FAIL(status) (status < 0)
#endif

#ifndef NT_SUCCESS
	#define NT_SUCCESS(status) (status >= 0)
#endif

#ifdef RtlMoveMemory
#undef RtlMoveMemory
#endif

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED	0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH  0x00000002
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER	0x00000004

#define OBJ_CASE_INSENSITIVE 0x00000040

#define STATUS_SUCCESS				0x00000000
#define STATUS_UNSUCCESSFUL			0xC0000001
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

#define LDR_GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT   0x00000001

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

typedef enum class _OBEJECT_TYPE_NUMBER
{
	Process = 0x07
} OBJECT_TYPE_NUMBER;

typedef enum class _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;

enum class LDR_DDAG_STATE
{
	LdrModulesReadyToRun = 9
};

typedef enum _FILE_INFORMATION_CLASS
{
	FileStandardInformation = 5,
	FilePositionInformation = 14
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

#pragma endregion

#pragma region structs

typedef struct _ANSI_STRING
{
	USHORT	Length;
	USHORT	MaxLength;
	char *  szBuffer;
} ANSI_STRING, *PANSI_STRING;

typedef struct _UNICODE_STRING
{
	WORD		Length;
	WORD		MaxLength;
	wchar_t *	szBuffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDRP_UNICODE_STRING_BUNDLE
{
	UNICODE_STRING	String;
	WCHAR			StaticBuffer[128];
} LDRP_UNICODE_STRING_BUNDLE, *PLDRP_UNICODE_STRING_BUNDLE;

typedef struct _RTL_BALANCED_NODE
{
	union
	{
		struct _RTL_BALANCED_NODE * Children[2];
		struct
		{
			struct _RTL_BALANCED_NODE * Left;
			struct _RTL_BALANCED_NODE * Right;
		};
	};
	
	union
	{
	    UCHAR Red : 1;
		UCHAR Balance : 2;
		ULONG_PTR ParentValue;
	};
} RTL_BALANCED_NODE, *PRTL_BALANCED_NODE;

typedef struct _RTL_RB_TREE
{
	RTL_BALANCED_NODE * Root;
	RTL_BALANCED_NODE * Min;
} RTL_RB_TREE, *PRTL_RB_TREE;

struct _LDR_DDAG_NODE;

typedef struct _LDRP_INCOMING_DEPENDENCY
{
	_LDRP_INCOMING_DEPENDENCY * Next;
	_LDR_DDAG_NODE * Node;
} LDRP_INCOMING_DEPENDENCY, *PLDRP_INCOMING_DEPENDENCY;

typedef struct _LDRP_DEPENDENCY
{
	_LDRP_DEPENDENCY			*	Next;
	_LDR_DDAG_NODE				*	DependencyNode;
	_LDRP_INCOMING_DEPENDENCY	*	IncomingDependenciesLink;
	_LDR_DDAG_NODE				*	ParentNode;
} LDRP_DEPENDENCY, *PLDRP_DEPENDENCY;

typedef struct _LDRP_CSLIST
{
	PSINGLE_LIST_ENTRY Tail;
} LDRP_CSLIST, * PLDRP_CSLIST;

typedef struct _LDR_DDAG_NODE
{
	LIST_ENTRY					Modules;
	PVOID						ServiceTagList;
	ULONG						LoadCount;
	ULONG						LoadWhileUnloadingCount;
	ULONG						LowestLink;
	PLDRP_DEPENDENCY			Dependencies;
	PLDRP_INCOMING_DEPENDENCY	IncomingDependencies;
	LDR_DDAG_STATE				State;
	PVOID						CondenseLink;
	ULONG						PreorderNumber;
} LDR_DDAG_NODE, *PLDR_DDAG_NODE;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY		InLoadOrderLinks;
	LIST_ENTRY		InMemoryOrderLinks;
	union
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};

	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;

	UNICODE_STRING	FullDllName;
	UNICODE_STRING	BaseDllName;

	ULONG	Flags;
	WORD	ObsoleteLoadCount;
	WORD	TlsIndex;

	LIST_ENTRY HashLinks;

	ULONG TimedateStamp;
	PVOID EntryPointActivationContext;
	PVOID Lock;

	LDR_DDAG_NODE *	DdagNode;

	LIST_ENTRY	NodeModuleLink;
	PVOID		LoadContext;
	PVOID		ParentDllBase;
	PVOID		SwitchBackContext;

	RTL_BALANCED_NODE BaseAddressIndexNode;
	RTL_BALANCED_NODE MappingInfoIndexNode;

	ULONG_PTR		OriginalBase;
	LARGE_INTEGER	LoadTime;
	ULONG			BaseNameHashValue;
	ULONG			LoadReason;

	ULONG ImplicitPathOptions;
	ULONG ReferenceCount;
	ULONG DependentLoadFlags;
	UCHAR SigningLevel;
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

typedef struct _FILE_STANDARD_INFORMATION 
{
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG         NumberOfLinks;
	BOOLEAN       DeletePending;
	BOOLEAN       Directory;
} FILE_STANDARD_INFORMATION, * PFILE_STANDARD_INFORMATION;

typedef struct _FILE_POSITION_INFORMATION
{
	LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, *PFILE_POSITION_INFORMATION;

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
	LDRP_UNICODE_STRING_BUNDLE	OriginalFullDllName;
} LDRP_PATH_SEARCH_CONTEXT, *PLDRP_PATH_SEARCH_CONTEXT;

typedef union _LDRP_LOAD_CONTEXT_FLAGS
{
	ULONG32 Flags;
	struct
	{
		ULONG32 Redirected					: 1;
		ULONG32 BaseNameOnly				: 1;
		ULONG32 HasFullPath					: 1;
		ULONG32 KnownDll					: 1;
		ULONG32 SystemImage					: 1;
		ULONG32 ExecutableImage				: 1;
		ULONG32 AppContainerImage			: 1;
		ULONG32 CallInit					: 1;
		ULONG32 UserAllocated				: 1;
		ULONG32 SearchOnlyFirstPathSegment	: 1;
		ULONG32 RedirectedByAPISet			: 1;
	};
} LDRP_LOAD_CONTEXT_FLAGS, * PLDRP_LOAD_CONTEXT_FLAGS;

typedef struct _OBJECT_ATTRIBUTES 
{
	ULONG				Length;
	HANDLE				RootDirectory;
	UNICODE_STRING	*	ObjectName;
	ULONG				Attributes;
	PVOID				SecurityDescriptor;
	PVOID				SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) \
{ \
	(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
	(p)->RootDirectory				= r; \
	(p)->Attributes					= a; \
	(p)->ObjectName					= n; \
	(p)->SecurityDescriptor			= s; \
	(p)->SecurityQualityOfService	= NULL; \
}

typedef struct _IO_STATUS_BLOCK 
{
	union 
	{
		NTSTATUS Status;
		PVOID Pointer;
	} DUMMYUNIONNAME;

	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

#ifdef _WIN64

typedef ALIGN_86 struct _ANSI_STRING32
{
	WORD	Length;
	WORD	MaxLength;
	DWORD	szBuffer;
} ANSI_STRING32, *PANSI_STRING32;

typedef ALIGN_86 struct _UNICODE_STRING32
{
	WORD	Length;
	WORD	MaxLength;
	DWORD	szBuffer;
} UNICODE_STRING32, *PUNICODE_STRING32;

typedef ALIGN_86 struct _LDRP_PATH_SEARCH_CONTEXT32
{
	UNICODE_STRING32			DllSearchPath;
	BOOLEAN						AllocatedOnLdrpHeap;
	LDRP_PATH_SEARCH_OPTIONS	SearchOptions;
	UNICODE_STRING32			OriginalFullDllName;
} LDRP_PATH_SEARCH_CONTEXT32, *PLDRP_PATH_SEARCH_CONTEXT32;

typedef ALIGN_86 struct _DDAG_DEPENDENCY32
{
	DWORD Next;
	DWORD DDag;
} DDAG_DEPENDENCY32, *PDDAG_DEPENDENCY32;

typedef ALIGN_86 struct _LDR_DDAG_NODE32
{
	LIST_ENTRY32 modules;
	DWORD ServiceTagList;
	DWORD LoadCount;
	DWORD LoadWhileUnloadingCount;
	DWORD LowestLink;
	DWORD Dependencies;
	DWORD IncomingDependencies;
	DWORD State;
	DWORD CondenseLink;
	DWORD PreorderNumber;
} LDR_DDAG_NODE32, *PLDR_DDAG_NODE32;

typedef ALIGN_86 struct _RTL_BALANCED_NODE32
{
	union
	{
		DWORD Children[2];
		struct
		{
			DWORD Left;
			DWORD Right;
		};
	};

	union
	{
		UCHAR Red : 1;
		UCHAR Balance : 2;
		DWORD ParentValue;
	};
} RTL_BALANCED_NODE32, *PRTL_BALANCED_NODE32;

typedef ALIGN_86 struct _LARGE_INTEGER32
{
	DWORD LowPart;
	DWORD HighPart;
} LARGE_INTEGER32, *PLARGE_INTEGER32;

typedef ALIGN_86 struct _LDR_DATA_TABLE_ENTRY32
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
	LIST_ENTRY32		HashLinks;
	ULONG				TimedateStamp;
	DWORD				EntryPointActivationContext;
	DWORD				Lock;
	DWORD				DdagNode;
	LIST_ENTRY32		NodeModuleLink;
	DWORD				LoadContext;
	DWORD				ParentDllBase;
	DWORD				SwitchBackContext;
	RTL_BALANCED_NODE32	BaseAddressIndexNode;
	RTL_BALANCED_NODE32	MappingInfoIndexNode;
	DWORD				OriginalBase;
	DWORD				Buffer;
	LARGE_INTEGER32		LoadTime;
	ULONG				BaseNameHashValue;
	ULONG				LoadReason;
	ULONG				ImplicitPathOptions;
	ULONG				ReferenceCount;
	ULONG				DependentLoadFlags;
	UCHAR				SigningLevel;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

typedef ALIGN_86 struct _PEB_LDR_DATA32
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

typedef ALIGN_86 struct _PEB32
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
	LDRP_LOAD_CONTEXT_FLAGS			Flags,
	LDR_DATA_TABLE_ENTRY		**	ldr_out
);

using f_LdrUnloadDll = NTSTATUS(__stdcall*)
(
	HINSTANCE hDll
);

using f_LdrGetDllHandleEx = NTSTATUS (__fastcall*)
(
	ULONG				Flags,
	PWSTR				OptDllPath,
	PULONG				OptDllCharacteristics,
	UNICODE_STRING	*	DllName,
	PVOID			*	DllHandle
);

using f_LdrGetProcedureAddress = NTSTATUS (__stdcall*)
(
	PVOID				BaseAddress,
	ANSI_STRING		*	Name,
	ULONG				Ordinal,
	PVOID			*	ProcedureAddress
);

using f_LdrLockLoaderLock = NTSTATUS (__stdcall*)
(
	ULONG			Flags,
	ULONG		*	State,
	ULONG_PTR	*	Cookie
);

using f_LdrUnlockLoaderLock = NTSTATUS (__stdcall*)
(
	ULONG Flags,
	ULONG_PTR Cookie
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

using f_LdrpPreprocessDllName = NTSTATUS (__fastcall*)
(
	UNICODE_STRING				* DllName,
	LDRP_UNICODE_STRING_BUNDLE	* OutputDllName,
	LDR_DATA_TABLE_ENTRY		* pOptParentEntry,
	LDRP_LOAD_CONTEXT_FLAGS		* LoadContextFlags
);

using f_RtlInsertInvertedFunctionTable = BOOL (__fastcall*)
(
	void	*	hDll,
	DWORD		SizeOfImage
);

using f_LdrpHandleTlsData = NTSTATUS (__fastcall*)
(
	LDR_DATA_TABLE_ENTRY * pEntry
);

using f_RtlMoveMemory = VOID (__stdcall*)
(
	PVOID	UNALIGNED	Destination,
	LPCVOID	UNALIGNED	Source,
	SIZE_T				Length
);

using f_RtlAllocateHeap = PVOID (__stdcall*)
(
	PVOID	HeapHandle,
	ULONG	Flags,
	SIZE_T	Size
);

using f_RtlFreeHeap = BOOLEAN (__stdcall*)
(
	PVOID	HeapHandle,
	ULONG	Flags,
	PVOID	BaseAddress
);

using f_RtlAnsiStringToUnicodeString = NTSTATUS (__stdcall*)
(
	UNICODE_STRING	*	DestinationString,
	ANSI_STRING		*	SourceString,
	BOOLEAN				AllocateDestinationString
);

using f_RtlUnicodeStringToAnsiString = NTSTATUS (__stdcall*)
(
	ANSI_STRING		*	DestinationString,
	UNICODE_STRING	*	SourceString,
	BOOLEAN				AllocateDestinationString
);

using f_RtlInitUnicodeString = VOID (__stdcall*)
(
	UNICODE_STRING * DestinationString,
	const wchar_t * SourceString
);

using f_RtlHashUnicodeString = NTSTATUS (__stdcall*)
(
	UNICODE_STRING	*	String,
	BOOLEAN				CaseInSensitive,
	ULONG				HashAlgorithm,
	ULONG			*	HashValue
);

using f_RtlRbInsertNodeEx = VOID (__stdcall*)
(
	RTL_RB_TREE			*	pTree,
	RTL_BALANCED_NODE	*	pOptParent,
	BOOLEAN					Right,
	RTL_BALANCED_NODE	*	pNode
);

using f_RtlRbRemoveNode = VOID (__stdcall*)
(
	RTL_RB_TREE			* pTree,
	RTL_BALANCED_NODE	* pNode
);

using f_NtOpenFile = NTSTATUS (__stdcall*)
(
	HANDLE				*	hFileOut,
	ACCESS_MASK				DesiredAccess,
	OBJECT_ATTRIBUTES	*	pAtrributes,
	IO_STATUS_BLOCK		*	pIoStatusBlock,
	ULONG					ShareAccess,
	ULONG					OpenOptions
);

using f_NtReadFile = NTSTATUS (__stdcall*)
(
	HANDLE					FileHandle,
	HANDLE					hOptEvent,
	PVOID					pOptApc,
	PVOID					pOptApcContext,
	IO_STATUS_BLOCK		*	IoStatusBlock,
	PVOID					Buffer,
	ULONG					Length,
	LARGE_INTEGER		*	pOptByteOffset,
	ULONG				*	pOptKey
);

using f_NtSetInformationFile = NTSTATUS (__stdcall*)
(
	HANDLE						FileHandle,
	IO_STATUS_BLOCK			*	IoStatusBlock,
	PVOID						FileInformation,
	ULONG						Length,
	FILE_INFORMATION_CLASS		FileInformationClass
);

using f_NtQueryInformationFile = NTSTATUS(__stdcall*)
(
	HANDLE						FileHandle,
	IO_STATUS_BLOCK			*	pIoStatusBlock,
	PVOID						FileInformation,
	ULONG						Length,
	FILE_INFORMATION_CLASS		FileInformationClass
);

using f_NtCreateSection = NTSTATUS (__stdcall*)
(
	PHANDLE			SectionHandle,
	ACCESS_MASK		DesiredAccess,
	PVOID			ObjectAttributes,
	PLARGE_INTEGER	MaximumSize,
	ULONG			SectionPageProtection,
	ULONG			AllocationAttributes,
	HANDLE			FileHandle
);

using f_NtMapViewOfSection = NTSTATUS (__stdcall*)
(
	HANDLE				SectionHandle,
	HANDLE				ProcessHandle,
	PVOID			*	BaseAddress,
	ULONG_PTR			ZeroBits,
	SIZE_T				CommitSize,
	PLARGE_INTEGER		SectionOffset,
	PSIZE_T				ViewSize,
	SECTION_INHERIT		InheritDisposition,
	ULONG				AllocationType,
	ULONG				Win32Protect
);

using f_NtUnmapViewOfSection = NTSTATUS (__stdcall*)
(
	HANDLE	ProcessHandle,
	PVOID	BaseAddress
);

using f_NtClose = NTSTATUS (__stdcall*)
(
	HANDLE Handle
);

using f_NtAllocateVirtualMemory = NTSTATUS (__stdcall*)
(
	HANDLE			ProcessHandle,
	PVOID		*	BaseAddress,
	ULONG_PTR		ZeroBits,
	SIZE_T		*	RegionSize,
	ULONG			AllocationType,
	ULONG			Protect
);

using f_NtFreeVirtualMemory = NTSTATUS (__stdcall*)
(
	HANDLE		ProcessHandle,
	PVOID	*	BaseAddress,
	SIZE_T	*	RegionSize,
	ULONG		FreeType
);

using f_NtProtectVirtualMemory = NTSTATUS (__stdcall*)
(
	HANDLE		ProcessHandle,
	PVOID	*	BaseAddress,
	SIZE_T	*	Size,
	ULONG		NewAccess,
	ULONG	*	OldAccess
);

using f_RtlGetSystemTimePrecise = LONGLONG (__stdcall*)
(

);

using f_LdrpModuleBaseAddressIndex	= RTL_RB_TREE*;
using f_LdrpMappingInfoIndex		= RTL_RB_TREE*;
using f_LdrpHashTable				= LIST_ENTRY*;
using f_LdrpHeap					= PVOID*;

#pragma endregion

inline HINSTANCE g_hNTDLL;