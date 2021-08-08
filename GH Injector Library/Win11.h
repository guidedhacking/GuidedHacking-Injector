#pragma once

#include "NT Defs.h"

typedef struct _LDR_DDAG_NODE_WIN11
{
	LIST_ENTRY				Modules;
	PLDR_SERVICE_TAG_RECORD	ServiceTagList;
	ULONG					LoadCount;
	ULONG					LoadWhileUnloadingCount;
	ULONG					LowestLink;
	PLDRP_CSLIST			Dependencies;
	PLDRP_CSLIST			IncomingDependencies;
	LDR_DDAG_STATE			State;
	SINGLE_LIST_ENTRY		CondenseLink;
	ULONG					PreorderNumber;
} LDR_DDAG_NODE_WIN11, * PLDR_DDAG_NODE_WIN11;

typedef struct _LDR_DATA_TABLE_ENTRY_WIN11
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;

	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;

	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;

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
			ULONG LoadConfigProcessed		: 1;
			ULONG EntryProcessed			: 1;
			ULONG ProtectDelayLoad			: 1;
			ULONG ReservedFlags3			: 2;
			ULONG DontCallForThreads		: 1;
			ULONG ProcessAttachCalled		: 1;
			ULONG ProcessAttachFailed		: 1;
			ULONG CorDeferredValidate		: 1;
			ULONG CorImage					: 1;
			ULONG DontRelocate				: 1;
			ULONG CorILOnly					: 1;
			ULONG ChpeImage					: 1;
			ULONG ReservedFlags5			: 2;
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
	PVOID Lock;

	LDR_DDAG_NODE_WIN11 * DdagNode;

	LIST_ENTRY	NodeModuleLink;
	PVOID		LoadContext;
	PVOID		ParentDllBase;
	PVOID		SwitchBackContext;

	RTL_BALANCED_NODE BaseAddressIndexNode;
	RTL_BALANCED_NODE MappingInfoIndexNode;

	ULONG_PTR			OriginalBase;
	LARGE_INTEGER		LoadTime;
	ULONG				BaseNameHashValue;
	LDR_DLL_LOAD_REASON	LoadReason;
	ULONG				ImplicitPathOptions;

	ULONG ReferenceCount;
	ULONG DependentLoadFlags;
	UCHAR SigningLevel;

	ULONG CheckSum;
	PVOID ActivePathImageBase;
	LDR_HOT_PATCH_STATE HotPatchState;
} LDR_DATA_TABLE_ENTRY_WIN11, * PLDR_DATA_TABLE_ENTRY_WIN11;

#ifdef _WIN64

typedef ALIGN_86 struct _LDR_DDAG_NODE_WIN11_32
{
	LIST_ENTRY32			Modules;
	DWORD					ServiceTagList; // -> LDR_SERVICE_TAG_RECORD_32
	ULONG					LoadCount;
	ULONG					LoadWhileUnloadingCount;
	ULONG					LowestLink;
	DWORD					Dependencies; // -> LDRP_CSLIST_32
	DWORD					IncomingDependencies; // -> LDRP_CSLIST_32
	LDR_DDAG_STATE			State;
	SINGLE_LIST_ENTRY_32	CondenseLink;
	ULONG					PreorderNumber;
} LDR_DDAG_NODE_WIN11_32, * PLDR_DDAG_NODE_WIN11_32;

typedef struct _LDR_DATA_TABLE_ENTRY_WIN11_32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;

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
			ULONG LoadConfigProcessed		: 1;
			ULONG EntryProcessed			: 1;
			ULONG ProtectDelayLoad			: 1;
			ULONG ReservedFlags3			: 2;
			ULONG DontCallForThreads		: 1;
			ULONG ProcessAttachCalled		: 1;
			ULONG ProcessAttachFailed		: 1;
			ULONG CorDeferredValidate		: 1;
			ULONG CorImage					: 1;
			ULONG DontRelocate				: 1;
			ULONG CorILOnly					: 1;
			ULONG ChpeImage					: 1;
			ULONG ReservedFlags5			: 2;
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

	DWORD DdagNode; // -> LDR_DDAG_NODE_WIN11_32

	LIST_ENTRY32	NodeModuleLink;
	DWORD			LoadContext;
	DWORD			ParentDllBase;
	DWORD			SwitchBackContext;

	RTL_BALANCED_NODE_32 BaseAddressIndexNode;
	RTL_BALANCED_NODE_32 MappingInfoIndexNode;

	DWORD				OriginalBase;
	LARGE_INTEGER		LoadTime;
	ULONG				BaseNameHashValue;
	LDR_DLL_LOAD_REASON	LoadReason;
	ULONG				ImplicitPathOptions;

	ULONG ReferenceCount;
	ULONG DependentLoadFlags;
	UCHAR SigningLevel;

	ULONG CheckSum;
	DWORD ActivePathImageBase;
	LDR_HOT_PATCH_STATE HotPatchState;
} LDR_DATA_TABLE_ENTRY_WIN11_32, * PLDR_DATA_TABLE_ENTRY_WIN11_32;

#endif