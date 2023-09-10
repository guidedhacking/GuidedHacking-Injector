/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

#pragma once

#include "pch.h"

#pragma region nt (un)defines

#ifndef NT_FAIL
#define NT_FAIL(status) (status < 0)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (status >= 0)
#endif

#ifdef memmove
#undef memmove
#endif

#ifdef RtlZeroMemory
#undef RtlZeroMemory
#endif

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED	0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH	0x00000002 //broken?!
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER	0x00000004

#define OBJ_CASE_INSENSITIVE 0x00000040

#define STATUS_SUCCESS				0x00000000
#define STATUS_UNSUCCESSFUL			0xC0000001
#define STATUS_NOT_IMPLEMENTED		0xC0000002
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define STATUS_APISET_NOT_HOSTED	0xC0000481

#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020

////
#define FILE_DELETE_ON_CLOSE                    0x00001000
#define FILE_OPEN_BY_FILE_ID                    0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT             0x00004000
#define FILE_NO_COMPRESSION                     0x00008000

#define FILE_RESERVE_OPFILTER                   0x00100000
#define FILE_OPEN_REPARSE_POINT                 0x00200000
#define FILE_OPEN_NO_RECALL                     0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY          0x00800000
////


#define InitializeObjectAttributes(p, n, a, r, s) \
{ \
	(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
	(p)->RootDirectory				= r; \
	(p)->Attributes					= a; \
	(p)->ObjectName					= n; \
	(p)->SecurityDescriptor			= s; \
	(p)->SecurityQualityOfService	= NULL; \
}

typedef LONG KPRIORITY;

#define KUSER_SHARED_DATA (DWORD)0x7FFE0000
#define P_KUSER_SHARED_DATA_COOKIE ReCa<DWORD *>(KUSER_SHARED_DATA + 0x0330)

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 ) 

#pragma endregion

#pragma region enums

typedef enum class _PROCESSINFOCLASS
{
	ProcessBasicInformation			= 0,
	ProcessSessionInformation		= 24,
	ProcessWow64Information			= 26,
	ProcessCookie					= 36,
	ProcessProtectionInformation	= 61
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

typedef enum class _KTHREAD_STATE
{
	Running = 0x02,
	Waiting = 0x05
} KTHREAD_STATE;

typedef enum class _KWAIT_REASON
{
	WrQueue = 0x0F
} KWAIT_REASON;

typedef enum class _OBEJECT_TYPE_NUMBER
{
	Process = 0x07
} OBJECT_TYPE_NUMBER;

typedef enum _FILE_INFORMATION_CLASS
{
	FileStandardInformation = 5,
	FilePositionInformation = 14
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef enum _LDR_DDAG_STATE : int
{
	LdrModulesMerged					= -5,
	LdrModulesInitError					= -4,
	LdrModulesSnapError					= -3,
	LdrModulesUnloaded					= -2,
	LdrModulesUnloading					= -1,
	LdrModulesPlaceHolder				= 0,
	LdrModulesMapping					= 1,
	LdrModulesMapped					= 2,
	LdrModulesWaitingForDependencies	= 3,
	LdrModulesSnapping					= 4,
	LdrModulesSnapped					= 5,
	LdrModulesCondensed					= 6,
	LdrModulesReadyToInit				= 7,
	LdrModulesInitializing				= 8,
	LdrModulesReadyToRun				= 9
} LDR_DDAG_STATE, * PLDR_DDAG_STATE;

typedef enum _LDR_DLL_LOAD_REASON : int
{
	LoadReasonUnknown						= -1,
	LoadReasonStaticDependency				= 0,
	LoadReasonStaticForwarderDependency		= 1,
	LoadReasonDynamicForwarderDependency	= 2,
	LoadReasonDelayloadDependency			= 3,
	LoadReasonDynamicLoad					= 4,
	LoadReasonAsImageLoad					= 5,
	LoadReasonAsDataLoad					= 6,
	LoadReasonEnclavePrimary				= 7, 
	LoadReasonEnclaveDependency				= 8,
	LoadReasonPatchImage					= 9
} LDR_DLL_LOAD_REASON, * PLDR_DLL_LOAD_REASON;

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

typedef enum _LDR_HOT_PATCH_STATE
{
    LdrHotPatchBaseImage		= 0,
    LdrHotPatchNotApplied		= 1,
    LdrHotPatchAppliedReverse	= 2,
    LdrHotPatchAppliedForward	= 3,
    LdrHotPatchFailedToPatch	= 4,
    LdrHotPatchStateMax			= 5
} LDR_HOT_PATCH_STATE, * PLDR_HOT_PATCH_STATE;

#pragma endregion

struct PEB;

typedef struct _ANSI_STRING
{
	USHORT	Length;
	USHORT	MaxLength;
	char *	szBuffer;
} ANSI_STRING, * PANSI_STRING;

typedef struct _UNICODE_STRING
{
	WORD		Length;
	WORD		MaxLength;
	wchar_t *	szBuffer;
} UNICODE_STRING, * PUNICODE_STRING;

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
		UCHAR Red		: 1;
		UCHAR Balance	: 2;
		ULONG_PTR ParentValue;
	};
} RTL_BALANCED_NODE, * PRTL_BALANCED_NODE;

typedef struct _RTL_RB_TREE
{
	RTL_BALANCED_NODE * Root;
	RTL_BALANCED_NODE * Min;
} RTL_RB_TREE, * PRTL_RB_TREE;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	WORD		UniqueProcessId;
	WORD		CreateBackTraceIndex;
	BYTE		ObjectTypeIndex;
	BYTE		HandleAttributes;
	WORD		HandleValue;
	void	*	Object;
	ULONG		GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS	ExitStatus;
	PVOID		TebBaseAddress;
	CLIENT_ID	ClientId;
	KAFFINITY	AffinityMask;
	KPRIORITY	Priority;
	KPRIORITY	BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

typedef struct _PROCESS_BASIC_INFORMATION
{
	NTSTATUS	ExitStatus;
	PEB	*		pPEB;
	ULONG_PTR	AffinityMask;
	LONG		BasePriority;
	HANDLE		UniqueProcessId;
	HANDLE		InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef struct _PROCESS_SESSION_INFORMATION
{
	ULONG SessionId;
} PROCESS_SESSION_INFORMATION, * PPROCESS_SESSION_INFORMATION;

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
	KTHREAD_STATE	ThreadState;
	KWAIT_REASON	WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

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
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

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
} FILE_POSITION_INFORMATION, * PFILE_POSITION_INFORMATION;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG				Length;
	HANDLE				RootDirectory;
	UNICODE_STRING *	ObjectName;
	ULONG				Attributes;
	PVOID				SecurityDescriptor;
	PVOID				SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS	Status;
		PVOID		Pointer;
	} DUMMYUNIONNAME;

	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _PEB_LDR_DATA
{
	ULONG		Length;
	BYTE		Initialized;
	HANDLE		SsHandle;
	LIST_ENTRY	InLoadOrderModuleListHead;
	LIST_ENTRY	InMemoryOrderModuleListHead;
	LIST_ENTRY	InInitializationOrderModuleListHead;
	PVOID		EntryInProgress;
	BYTE		ShutdownInProgress;
	HANDLE		ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

struct PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;

	union
	{
		UCHAR BitField;
		struct
		{
			UCHAR ImageUsedLargePages			: 1;
			UCHAR IsProtectedProcess			: 1;
			UCHAR IsImageDynamicallyRelocated	: 1;
			UCHAR SkipPatchingUser32Forwarders	: 1;
			UCHAR IsPackagedProcess				: 1;
			UCHAR IsAppContainer				: 1;
			UCHAR IsProtectedProcessLight		: 1;
			UCHAR IsLongPathAwareProcess		: 1;
		};
	};

	HANDLE Mutant;

	PVOID ImageBaseAddress;

	PEB_LDR_DATA * Ldr;

	PVOID					*	ProcessParameters;
	PVOID						SubSystemData;
	HANDLE						ProcessHeap;
	RTL_CRITICAL_SECTION	*	FastPebLock;
	PVOID						AtlThunkSListPtr;
	PVOID						IFEOKey;

	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob					: 1;
			ULONG ProcessInitializing			: 1;
			ULONG ProcessUsingVEH				: 1;
			ULONG ProcessUsingVCH				: 1;
			ULONG ProcessUsingFTH				: 1;
			ULONG ProcessPreviouslyThrottled	: 1;
			ULONG ProcessCurrentlyThrottled		: 1;
			ULONG ProcessImagesHotPatched		: 1;
			ULONG ReservedBits0					: 24;
		};
	};

#ifdef _WIN64
	UCHAR Padding1[4];
#endif

	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};

	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
	ULONG TlsExpansionCounter;

#ifdef _WIN64
	UCHAR Padding2[4];
#endif

	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;

	union
	{
		PVOID HotpatchInformation;	// till Win8
		PVOID SparePvoid0;			// Win8.1 -> Win10 (1607)
		PVOID SharedData;			// Win10 (1703) +
	};

	PVOID * ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	LARGE_INTEGER CriticalSectionTimeout;
	ULONG_PTR HeapSegmentReserve;
	ULONG_PTR HeapSegmentCommit;
	ULONG_PTR HeapDeCommitTotalFreeThreshold;
	ULONG_PTR HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID * ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;

#ifdef _WIN64
	UCHAR Padding3[4];
#endif

	RTL_CRITICAL_SECTION * LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;

	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
};

typedef struct _LDR_SERVICE_TAG_RECORD
{
	struct _LDR_SERVICE_TAG_RECORD * Next;
	ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, * PLDR_SERVICE_TAG_RECORD;

typedef struct _LDRP_CSLIST
{
	struct _SINGLE_LIST_ENTRY * Tail;
} LDRP_CSLIST, * PLDRP_CSLIST;

typedef struct _LDRP_UNICODE_STRING_BUNDLE
{
	UNICODE_STRING	String;
	WCHAR			StaticBuffer[128];
} LDRP_UNICODE_STRING_BUNDLE, * PLDRP_UNICODE_STRING_BUNDLE;

typedef struct _RTL_INVERTED_FUNCTION_TABLE_ENTRY
{
	IMAGE_RUNTIME_FUNCTION_ENTRY *	ExceptionDirectory;
	PVOID							ImageBase;
	ULONG							ImageSize;
	ULONG							ExceptionDirectorySize;
} RTL_INVERTED_FUNCTION_TABLE_ENTRY, * PRTL_INVERTED_FUNCTION_TABLE_ENTRY;

typedef struct _RTL_INVERTED_FUNCTION_TABLE
{
	ULONG Count;
	ULONG MaxCount;
	ULONG Epoch;
	UCHAR Overflow;
	RTL_INVERTED_FUNCTION_TABLE_ENTRY Entries[ANYSIZE_ARRAY];
} RTL_INVERTED_FUNCTION_TABLE, * PRTL_INVERTED_FUNCTION_TABLE;

typedef union _LDR_SEARCH_PATH
{
	BOOLEAN NoPath : 1;
	wchar_t * szSearchPath;
} LDR_SEARCH_PATH, * PLDR_SEARCH_PATH;

//Win10 1511
typedef struct _LDRP_PATH_SEARCH_CONTEXT_1511
{
	wchar_t *	DllSearchPathOut;
	void	*	Unknown_0[2];
	wchar_t *	OriginalFullDllName;
	void	*	unknown_1[7];
	ULONG64		unknown_2[4];
} LDRP_PATH_SEARCH_CONTEXT_1511, * PLDRP_PATH_SEARCH_CONTEXT_1511; //x86 size = 0x4C, x64 size = 0x78

//Win10 1507, 1607+
typedef struct _LDRP_PATH_SEARCH_CONTEXT
{
	wchar_t *	DllSearchPathOut;
	void	*	Unknown_0[3];
	wchar_t *	OriginalFullDllName;
	void	*	unknown_1[7];
	ULONG64		unknown_2[4];
} LDRP_PATH_SEARCH_CONTEXT, * PLDRP_PATH_SEARCH_CONTEXT; //x86 size <= 0x50, x64 size <= 0x80

typedef union _LDRP_LOAD_CONTEXT_FLAGS
{
	ULONG32 Flags;
	struct //These are very most likely wrong!
	{
		ULONG32 Redirected					: 1;
		ULONG32 Static						: 1;
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

typedef struct _RTL_VECTORED_HANDLER_LIST
{
	SRWLOCK     Lock;
	LIST_ENTRY  List;
} RTL_VECTORED_HANDLER_LIST, * PRTL_VECTORED_HANDLER_LIST;

typedef struct _RTL_VECTORED_EXCEPTION_ENTRY //Win7 till Win10 1909
{
	LIST_ENTRY					List;
	DWORD						Flag;
	PVECTORED_EXCEPTION_HANDLER	VectoredHandler;
} RTL_VECTORED_EXCEPTION_ENTRY, * PRTL_VECTORED_EXCEPTION_ENTRY;

typedef struct _RTL_VECTORED_EXCEPTION_ENTRY_WIN10_2004 //Win10 2004+
{
	LIST_ENTRY                  List;
	PULONG_PTR                  pFlag; //points to Flag
	ULONG                       RefCount;
	PVECTORED_EXCEPTION_HANDLER VectoredHandler;
	ULONG_PTR					Flag; //normally allocated somewhere else on LdrpMrdataHeap, just for convenience
} RTL_VECTORED_EXCEPTION_ENTRY_WIN10_2004, * PRTL_VECTORED_EXCEPTION_ENTRY_WIN10_2004;

typedef struct _TLS_ENTRY
{
	LIST_ENTRY				TlsEntryLinks;
	IMAGE_TLS_DIRECTORY		TlsDirectory;
	PVOID 					ModuleEntry; //LdrDataTableEntry
	SIZE_T					TlsIndex;
} TLS_ENTRY, * PTLS_ENTRY;

#ifdef _WIN64

typedef ALIGN_86 struct _UNICODE_STRING_32
{
	WORD	Length;
	WORD	MaxLength;
	DWORD	szBuffer;
} UNICODE_STRING_32, * PUNICODE_STRING_32;

typedef ALIGN_86 struct _RTL_BALANCED_NODE_32
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
		UCHAR Red		: 1;
		UCHAR Balance	: 2;
		DWORD ParentValue;
	};
} RTL_BALANCED_NODE_32, * PRTL_BALANCED_NODE_32;

typedef ALIGN_86 struct _SINGLE_LIST_ENTRY_32
{
	DWORD Next; // -> SINGLE_LIST_ENTRY_32
} SINGLE_LIST_ENTRY_32, * PSINGLE_LIST_ENTRY_32;

typedef ALIGN_86 struct _LDR_SERVICE_TAG_RECORD_32
{
	DWORD Next; // -> LDR_SERVICE_TAG_RECORD_32
	ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD_32, * PLDR_SERVICE_TAG_RECORD_32;

typedef ALIGN_86 struct _LDRP_CSLIST_32
{
	DWORD Tail; // -> SINGLE_LIST_ENTRY_32
} LDRP_CSLIST_32, * PLDRP_CSLIST_32;

typedef ALIGN_86 struct _RTL_CRITICAL_SECTION_32
{
	DWORD	DebugInfo; // -> RTL_CRITICAL_SECTION_DEBUG_32
	LONG	LockCount;
	LONG	RecursionCount;
	DWORD	OwningThread;
	DWORD	LockSemaphore;
	DWORD	SpinCount;
} RTL_CRITICAL_SECTION_32, * PRTL_CRITICAL_SECTION_32;

typedef ALIGN_86 struct _RTL_CRITICAL_SECTION_DEBUG_32
{
	WORD			Type;
	WORD			CreatorBackTraceIndex;
	DWORD			CriticalSection; // -> RTL_CRITICAL_SECTION_32
	LIST_ENTRY32	ProcessLocksList;
	DWORD			EntryCount;
	DWORD			ContentionCount;
	DWORD			Flags;
	WORD			CreatorBackTraceIndexHigh;
	WORD			SpareWORD;
} RTL_CRITICAL_SECTION_DEBUG_32, * PRTL_CRITICAL_SECTION_DEBUG_32, _RTL_RESOURCE_DEBUG_32, RTL_RESOURCE_DEBUG_32, * PRTL_RESOURCE_DEBUG_32;

typedef ALIGN_86 struct _PEB_LDR_DATA_32
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
} PEB_LDR_DATA_32, * PPEB_LDR_DATA_32;

typedef struct _PEB_32
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;

	union
	{
		UCHAR BitField;
		struct
		{
			UCHAR ImageUsedLargePages			: 1;
			UCHAR IsProtectedProcess			: 1;
			UCHAR IsImageDynamicallyRelocated	: 1;
			UCHAR SkipPatchingUser32Forwarders	: 1;
			UCHAR IsPackagedProcess				: 1;
			UCHAR IsAppContainer				: 1;
			UCHAR IsProtectedProcessLight		: 1;
			UCHAR IsLongPathAwareProcess		: 1;
		};
	};

	DWORD Mutant;

	DWORD ImageBaseAddress;
	DWORD Ldr; // -> PEB_LDR_DATA_32

	DWORD ProcessParameters;
	DWORD SubSystemData;
	DWORD ProcessHeap;
	DWORD FastPebLock; // -> RTL_CRITICAL_SECTION_32
	DWORD AtlThunkSListPtr;
	DWORD IFEOKey;

	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob					: 1;
			ULONG ProcessInitializing			: 1;
			ULONG ProcessUsingVEH				: 1;
			ULONG ProcessUsingVCH				: 1;
			ULONG ProcessUsingFTH				: 1;
			ULONG ProcessPreviouslyThrottled	: 1;
			ULONG ProcessCurrentlyThrottled		: 1;
			ULONG ProcessImagesHotPatched		: 1;
			ULONG ReservedBits0					: 24;
		};
	};

	union
	{
		DWORD KernelCallbackTable;
		DWORD UserSharedInfoPtr;
	};

	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	DWORD ApiSetMap;
	ULONG TlsExpansionCounter;

	DWORD TlsBitmap;
	ULONG TlsBitmapBits[2];
	DWORD ReadOnlySharedMemoryBase;

	union
	{
		DWORD HotpatchInformation;	// till Win8
		DWORD SparePvoid0;			// Win8.1 -> Win10 (1607)
		DWORD SharedData;			// Win10 (1703) +
	};

	DWORD ReadOnlyStaticServerData;
	DWORD AnsiCodePageData;
	DWORD OemCodePageData;
	DWORD UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	LARGE_INTEGER CriticalSectionTimeout;
	DWORD HeapSegmentReserve;
	DWORD HeapSegmentCommit;
	DWORD HeapDeCommitTotalFreeThreshold;
	DWORD HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	DWORD ProcessHeaps;
	DWORD GdiSharedHandleTable;
	DWORD ProcessStarterHelper;
	ULONG GdiDCAttributeList;

	DWORD LoaderLock; // -> RTL_CRITICAL_SECTION_32
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
} PEB_32, * PPEB_32;

typedef ALIGN_86 struct _LDRP_UNICODE_STRING_BUNDLE_32
{
	UNICODE_STRING_32	String;
	WCHAR				StaticBuffer[128];
} LDRP_UNICODE_STRING_BUNDLE_32, * PLDRP_UNICODE_STRING_BUNDLE_32;

typedef ALIGN_86 struct _LDRP_PATH_SEARCH_CONTEXT_32 //dummy structure, needs to be at least 0x50 bytes in size, members don't matter
{
	DWORD DllSearchPathOut; // wchar_t *
	DWORD unknown_0[3];
	DWORD OriginalFullDllName; // wchar_t *
	DWORD unknown_1[15];
} LDRP_PATH_SEARCH_CONTEXT_32, * PLDRP_PATH_SEARCH_CONTEXT_32;

typedef ALIGN_86 struct _RTL_INVERTED_FUNCTION_TABLE_ENTRY_32
{
	DWORD ExceptionDirectory; // -> IMAGE_RUNTIME_FUNCTION_ENTRY
	DWORD ImageBase;
	ULONG ImageSize;
	ULONG ExceptionDirectorySize;
} RTL_INVERTED_FUNCTION_TABLE_ENTRY_32, * PRTL_INVERTED_FUNCTION_TABLE_ENTRY_32;

typedef ALIGN_86 struct _RTL_INVERTED_FUNCTION_TABLE_32
{
	ULONG Count;
	ULONG MaxCount;
	ULONG Epoch;
	UCHAR Overflow;
	RTL_INVERTED_FUNCTION_TABLE_ENTRY_32 Entries[ANYSIZE_ARRAY];
} RTL_INVERTED_FUNCTION_TABLE_32, * PRTL_INVERTED_FUNCTION_TABLE_32;

typedef ALIGN_86 union _LDRP_PATH_SEARCH_OPTIONS_32
{
	ULONG32 Flags;

	struct
	{
		ULONG32 Unknown;
	};
} LDRP_PATH_SEARCH_OPTIONS_32, * PLDRP_PATH_SEARCH_OPTIONS_32;

typedef ALIGN_86 union _LDRP_LOAD_CONTEXT_FLAGS_32
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
} LDRP_LOAD_CONTEXT_FLAGS_32, * PLDRP_LOAD_CONTEXT_FLAGS_32;

typedef struct _RTL_VECTORED_HANDLER_LIST_32
{
	DWORD			Lock;
	LIST_ENTRY32	List;
} RTL_VECTORED_HANDLER_LIST_32, * PRTL_VECTORED_HANDLER_LIST_32;

typedef struct _RTL_VECTORED_EXCEPTION_ENTRY_32 //Win7 till Win10 1909
{
	LIST_ENTRY32	List;
	DWORD			Flag;
	DWORD			VectoredHandler;
} RTL_VECTORED_EXCEPTION_ENTRY_32, * PRTL_VECTORED_EXCEPTION_ENTRY_32;

typedef struct _RTL_VECTORED_EXCEPTION_ENTRY_WIN10_2004_32 //Win10 2004+
{
	LIST_ENTRY32	List;
	DWORD			pFlag; //DWORD *
	ULONG			RefCount;
	DWORD			VectoredHandler; //PVECTORED_EXCEPTION_HANDLER
	DWORD			Flag;
} RTL_VECTORED_EXCEPTION_ENTRY_WIN10_2004_32, * PRTL_VECTORED_EXCEPTION_ENTRY_WIN10_2004_32;

#endif