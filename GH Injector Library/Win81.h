#pragma once

#include "NT Defs.h"

typedef struct _LDR_DDAG_NODE_WIN81
{
	LIST_ENTRY				Modules;
	PLDR_SERVICE_TAG_RECORD	ServiceTagList;
	ULONG					LoadCount;
	ULONG					ReferenceCount;
	ULONG					DependencyCount;
	union
	{
		LDRP_CSLIST			Dependencies;
		SINGLE_LIST_ENTRY * RemovalLink;
	};
	PLDRP_CSLIST			IncomingDependencies;
	LDR_DDAG_STATE			State;
	SINGLE_LIST_ENTRY		CondenseLink;
	ULONG					PreorderNumber;
	ULONG					LowestLink;
} LDR_DDAG_NODE_WIN81, * PLDR_DDAG_NODE_WIN81;

typedef struct _LDR_DATA_TABLE_ENTRY_WIN81
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

	union
	{
		UCHAR FlagGroup[4];
		ULONG Flags;

		struct
		{
			ULONG PackagedBinary			: 1;
			ULONG MarkedForRemoval			: 1;
			ULONG ImageDll					: 1;
			ULONG LoadNotificationsSent		: 1;
			ULONG TelemetryEntryProcessed	: 1;
			ULONG ProcessStaticImport		: 1;
			ULONG InLegacyLists				: 1;
			ULONG InIndexes					: 1;
			ULONG ShimDll					: 1;
			ULONG InExceptionTable			: 1;
			ULONG ReservedFlags1			: 2;
			ULONG LoadInProgress			: 1;
			ULONG ReservedFlags2			: 1; 
			ULONG EntryProcessed			: 1;
			ULONG ReservedFlags3			: 3;
			ULONG DontCallForThreads		: 1;
			ULONG ProcessAttachCalled		: 1;
			ULONG ProcessAttachFailed		: 1;
			ULONG CorDeferredValidate		: 1;
			ULONG CorImage					: 1;
			ULONG DontRelocate				: 1;
			ULONG CorILOnly					: 1;
			ULONG ReservedFlags5			: 3;
			ULONG Redirected				: 1;
			ULONG ReservedFlags6			: 2;
			ULONG CompatDatabaseProcessed	: 1;
		};
	};

	WORD ObsoleteLoadCount;
	WORD TlsIndex;

	LIST_ENTRY HashLinks;

	ULONG TimedateStamp;
	PVOID EntryPointActivationContext;
	PVOID Spare;

	LDR_DDAG_NODE_WIN81 * DdagNode;

	LIST_ENTRY	NodeModuleLink;
	PVOID		SnapContext;
	PVOID		ParentDllBase;
	PVOID		SwitchBackContext;

	RTL_BALANCED_NODE BaseAddressIndexNode;
	RTL_BALANCED_NODE MappingInfoIndexNode;

	ULONG_PTR			OriginalBase;
	LARGE_INTEGER		LoadTime;
	ULONG				BaseNameHashValue;
	LDR_DLL_LOAD_REASON	LoadReason;

	ULONG ImplicitPathOptions;
} LDR_DATA_TABLE_ENTRY_WIN81, * PLDR_DATA_TABLE_ENTRY_WIN81;

typedef struct _LDRP_PATH_SEARCH_CONTEXT_WIN81
{
	UINT_PTR unknown_0[3];
	wchar_t * OriginalFullDllName;
	UINT_PTR unknown_1[1];
} LDRP_PATH_SEARCH_CONTEXT_WIN81, * PLDRP_PATH_SEARCH_CONTEXT_WIN81; //x86 size = 0x14, x64 size = 0x28

#ifdef _WIN64

typedef ALIGN_86 struct _LDR_DDAG_NODE_WIN81_32
{
	LIST_ENTRY32	Modules;
	DWORD			ServiceTagList; // -> LDR_SERVICE_TAG_RECORD_32
	ULONG			LoadCount;
	ULONG			ReferenceCount;
	ULONG			DependencyCount;
	union
	{
		LDRP_CSLIST_32	Dependencies;
		DWORD			RemovalLink; // -> SINGLE_LIST_ENTRY_32
	};
	DWORD					IncomingDependencies; // -> LDRP_CSLIST_32
	LDR_DDAG_STATE			State;
	SINGLE_LIST_ENTRY_32	CondenseLink;
	ULONG					PreorderNumber;
	ULONG					LowestLink;
} LDR_DDAG_NODE_WIN81_32, * PLDR_DDAG_NODE_WIN81_32;

typedef struct _LDR_DATA_TABLE_ENTRY_WIN81_32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	union
	{
		LIST_ENTRY32 InInitializationOrderLinks;
		LIST_ENTRY32 InProgressLinks;
	};

	DWORD DllBase;
	DWORD EntryPoint;
	ULONG SizeOfImage;

	UNICODE_STRING_32 FullDllName;
	UNICODE_STRING_32 BaseDllName;

	union
	{
		UCHAR FlagGroup[4];
		ULONG Flags;

		struct
		{
			ULONG PackagedBinary			: 1;
			ULONG MarkedForRemoval			: 1;
			ULONG ImageDll					: 1;
			ULONG LoadNotificationsSent		: 1;
			ULONG TelemetryEntryProcessed	: 1;
			ULONG ProcessStaticImport		: 1;
			ULONG InLegacyLists				: 1;
			ULONG InIndexes					: 1;
			ULONG ShimDll					: 1;
			ULONG InExceptionTable			: 1;
			ULONG ReservedFlags1			: 2;
			ULONG LoadInProgress			: 1;
			ULONG ReservedFlags2			: 1;
			ULONG EntryProcessed			: 1;
			ULONG ReservedFlags3			: 3;
			ULONG DontCallForThreads		: 1;
			ULONG ProcessAttachCalled		: 1;
			ULONG ProcessAttachFailed		: 1;
			ULONG CorDeferredValidate		: 1;
			ULONG CorImage					: 1;
			ULONG DontRelocate				: 1;
			ULONG CorILOnly					: 1;
			ULONG ReservedFlags5			: 3;
			ULONG Redirected				: 1;
			ULONG ReservedFlags6			: 2;
			ULONG CompatDatabaseProcessed	: 1;
		};
	};

	WORD ObsoleteLoadCount;
	WORD TlsIndex;

	LIST_ENTRY32 HashLinks;

	ULONG TimedateStamp;
	DWORD EntryPointActivationContext;
	DWORD Spare;

	DWORD DdagNode; // -> LDR_DDAG_NODE_WIN81_32

	LIST_ENTRY32	NodeModuleLink;
	DWORD			SnapContext;
	DWORD			ParentDllBase;
	DWORD			SwitchBackContext;

	RTL_BALANCED_NODE_32 BaseAddressIndexNode;
	RTL_BALANCED_NODE_32 MappingInfoIndexNode;

	DWORD				OriginalBase;
	LARGE_INTEGER		LoadTime;
	ULONG				BaseNameHashValue;
	LDR_DLL_LOAD_REASON	LoadReason;

	ULONG ImplicitPathOptions;
} LDR_DATA_TABLE_ENTRY_WIN81_32, * PLDR_DATA_TABLE_ENTRY_WIN81_32;

#endif