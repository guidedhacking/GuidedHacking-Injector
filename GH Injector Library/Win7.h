#pragma once

#include "NT Defs.h"

//some flags might not be Win7 but w/e, stolen from here:
//https://doxygen.reactos.org/d1/d97/ldrtypes_8h_source.html#l00034

//0x00000001
#define LDRP_STATIC_LINK				0x00000002
#define LDRP_IMAGE_DLL					0x00000004
#define LDRP_SHIMENG_ENTRY_PROCESSED	0x00000008
#define LDRP_TELEMETRY_ENTRY_PROCESSED	0x00000010
#define LDRP_IMAGE_INTEGRITY_FORCED		0x00000020
//0x00000040 - 0x00000800
#define LDRP_LOAD_IN_PROGRESS			0x00001000
#define LDRP_UNLOAD_IN_PROGRESS			0x00002000
#define LDRP_ENTRY_PROCESSED			0x00004000
#define LDRP_ENTRY_INSERTED				0x00008000  
#define LDRP_CURRENT_LOAD				0x00010000
#define LDRP_FAILED_BUILTIN_LOAD		0x00020000
#define LDRP_DONT_CALL_FOR_THREADS		0x00040000
#define LDRP_PROCESS_ATTACH_CALLED		0x00080000
#define LDRP_DEBUG_SYMBOLS_LOADED		0x00100000 
#define LDRP_IMAGE_NOT_AT_BASE			0x00200000 
#define LDRP_COR_IMAGE					0x00400000 
#define LDR_COR_OWNS_UNMAP				0x00800000 
#define LDRP_SYSTEM_MAPPED				0x01000000 
#define LDRP_IMAGE_VERIFYING			0x02000000 
#define LDRP_DRIVER_DEPENDENT_DLL		0x04000000 
#define LDRP_ENTRY_NATIVE				0x08000000 
#define LDRP_REDIRECTED					0x10000000 
#define LDRP_NON_PAGED_DEBUG_INFO		0x20000000 
#define LDRP_MM_LOADED					0x40000000 
#define LDRP_COMPAT_DATABASE_PROCESSED	0x80000000

typedef struct _LDR_DDAG_NODE_WIN7 //dummy for macros
{
} LDR_DDAG_NODE_WIN7, * PLDR_DDAG_NODE_WIN7;

typedef struct _LDR_DATA_TABLE_ENTRY_WIN7
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;

	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;

	UNICODE_STRING	FullDllName;
	UNICODE_STRING	BaseDllName;

	ULONG	Flags;
	WORD	LoadCount;
	WORD	TlsIndex;

	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};

	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};

	PVOID EntryPointActivationContext;
	PVOID PatchInformation;

	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;

	PVOID			ContextInformation;
	ULONG_PTR		OriginalBase;
	LARGE_INTEGER	LoadTime;
} LDR_DATA_TABLE_ENTRY_WIN7, * PLDR_DATA_TABLE_ENTRY_WIN7;

typedef struct _RTL_INVERTED_FUNCTION_TABLE_WIN7
{
	ULONG Count;
	ULONG MaxCount;
	ULONG Epoch;
	RTL_INVERTED_FUNCTION_TABLE_ENTRY Entries[ANYSIZE_ARRAY];
} RTL_INVERTED_FUNCTION_TABLE_WIN7, * PRTL_INVERTED_FUNCTION_TABLE_WIN7;

#ifdef _WIN64

typedef struct _LDR_DDAG_NODE_WIN7_32 //dummy for macros
{
} LDR_DDAG_NODE_WIN7_32, * PLDR_DDAG_NODE_WIN7_32;

typedef struct _LDR_DATA_TABLE_ENTRY_WIN7_32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;

	DWORD DllBase;
	DWORD EntryPoint;
	ULONG SizeOfImage;

	UNICODE_STRING_32 FullDllName;
	UNICODE_STRING_32 BaseDllName;

	ULONG	Flags;
	WORD	LoadCount;
	WORD	TlsIndex;

	union
	{
		LIST_ENTRY32 HashLinks;
		struct
		{
			DWORD SectionPointer;
			ULONG CheckSum;
		};
	};

	union
	{
		ULONG TimeDateStamp;
		DWORD LoadedImports;
	};

	DWORD EntryPointActivationContext;
	DWORD PatchInformation;

	LIST_ENTRY32 ForwarderLinks;
	LIST_ENTRY32 ServiceTagLinks;
	LIST_ENTRY32 StaticLinks;

	DWORD			ContextInformation;
	DWORD			OriginalBase;
	LARGE_INTEGER	LoadTime;
} LDR_DATA_TABLE_ENTRY_WIN7_32, * PLDR_DATA_TABLE_ENTRY_WIN7_32;

typedef struct _RTL_VECTORED_EXCEPTION_ENTRY_WIN7_32 //prototype
{
	LIST_ENTRY32	List;
	DWORD			Flag;
	DWORD			VectoredHandler; //PVECTORED_EXCEPTION_HANDLER
} RTL_VECTORED_EXCEPTION_ENTRY_WIN7_32, * PRTL_VECTORED_EXCEPTION_ENTRY_WIN7_32;

#endif