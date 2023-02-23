#pragma once

//I honestly can't give proper credit here as most of the stuff is stolen from somewhere ages ago
//Sources I definitely stole from:
//https://www.geoffchappell.com
//https://github.com/DarthTon
//https://github.com/reactos
//Bill Gates

#include "Win7.h"
#include "Win8.h"
#include "Win81.h"
#include "Win10.h"
#include "Win11.h"

#define DEF_STRUCT_DEFAULT(name, suffix)	\
using name		= name##suffix;				\
using P##name	= P##name##suffix;			\
using _##name	= _##name##suffix;

#define DEF_STRUCT_DEFAULT_32(name, suffix)	\
using name##_32		= name##suffix##_32;	\
using P##name##_32	= P##name##suffix##_32;	\
using _##name##_32	= _##name##suffix##_32;

#ifndef _WIN32_WINNT
	#error Not supported
#else
	#if(_WIN32_WINNT == _WIN32_WINNT_WIN7)
		DEF_STRUCT_DEFAULT(LDR_DATA_TABLE_ENTRY, _WIN7)
		DEF_STRUCT_DEFAULT(LDR_DDAG_NODE, _WIN7)

		#ifdef _WIN64
			DEF_STRUCT_DEFAULT_32(LDR_DATA_TABLE_ENTRY, _WIN7)
			DEF_STRUCT_DEFAULT_32(LDR_DDAG_NODE, _WIN7)
		#endif
	#elif (_WIN32_WINNT == _WIN32_WINNT_WIN8)
		DEF_STRUCT_DEFAULT(LDR_DATA_TABLE_ENTRY, _WIN8)
		DEF_STRUCT_DEFAULT(LDR_DDAG_NODE, _WIN8)

		#ifdef _WIN64
			DEF_STRUCT_DEFAULT_32(LDR_DATA_TABLE_ENTRY, _WIN8)
			DEF_STRUCT_DEFAULT_32(LDR_DDAG_NODE, _WIN8)
		#endif
	#elif (_WIN32_WINNT == _WIN32_WINNT_WINBLUE)
		DEF_STRUCT_DEFAULT(LDR_DATA_TABLE_ENTRY, _WIN81)
		DEF_STRUCT_DEFAULT(LDR_DDAG_NODE, _WIN81)

		#ifdef _WIN64
			DEF_STRUCT_DEFAULT_32(LDR_DATA_TABLE_ENTRY, _WIN81)
			DEF_STRUCT_DEFAULT_32(LDR_DDAG_NODE, _WIN81)
		#endif
	#elif (_WIN32_WINNT == _WIN32_WINNT_WIN10) //includes Win11
		#if (WDK_NTDDI_VERSION >= NTDDI_WIN10_CO) //Win11 SDK is called NTDDI_WIN10_CO
			DEF_STRUCT_DEFAULT(LDR_DATA_TABLE_ENTRY, _WIN11)
			DEF_STRUCT_DEFAULT(LDR_DDAG_NODE, _WIN11)

			#ifdef _WIN64
				DEF_STRUCT_DEFAULT_32(LDR_DATA_TABLE_ENTRY, _WIN11)
				DEF_STRUCT_DEFAULT_32(LDR_DDAG_NODE, _WIN11)
			#endif
		#else
			DEF_STRUCT_DEFAULT(LDR_DATA_TABLE_ENTRY, _WIN10)
			DEF_STRUCT_DEFAULT(LDR_DDAG_NODE, _WIN10)

			#ifdef _WIN64
				DEF_STRUCT_DEFAULT_32(LDR_DATA_TABLE_ENTRY, _WIN10)
				DEF_STRUCT_DEFAULT_32(LDR_DDAG_NODE, _WIN10)
			#endif
		#endif
	#else
		#error Not supported
	#endif
#endif

#pragma region function prototypes

using f_NtCreateThreadEx = NTSTATUS (__stdcall *)	
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

using f_LdrLoadDll = NTSTATUS (__stdcall *)
(
	LDR_SEARCH_PATH		ldrSearchPath,
	ULONG			*	pFlags,
	UNICODE_STRING	*	pModuleFileName,
	HANDLE			*	pOut
);

using f_LdrLoadDll_WIN8 = NTSTATUS (__stdcall *)
(
	BOOLEAN				Unknown1, //set to TRUE
	ULONG			*	LoadFlags,
	UNICODE_STRING	*	pModuleFileName,
	HANDLE			*	pOut
);

using f_LdrUnloadDll = NTSTATUS (__stdcall *)
(
	HANDLE DllHandle
);

using f_LdrpLoadDll_WIN7 = NTSTATUS (__stdcall *)
(
	UNICODE_STRING				*	dll_path,
	UNICODE_STRING				*	search_path,
	LDRP_LOAD_CONTEXT_FLAGS			Flags,
	BOOLEAN							Unknown1, //set to TRUE
	PVOID							Unknown2, //can be nullptr
	LDR_DATA_TABLE_ENTRY_WIN7	**	ldr_out
);

using f_LdrpLoadDll_WIN8 = NTSTATUS (__stdcall *)
(
	UNICODE_STRING					*	dll_path,
	LDRP_PATH_SEARCH_CONTEXT_WIN8	*	search_ctx,
	LDRP_LOAD_CONTEXT_FLAGS				Flags,
	BOOLEAN								Unknown, //set to TRUE
	LDR_DATA_TABLE_ENTRY_WIN8		**	entry_out,
	LDR_DDAG_NODE_WIN8				**	ddag_out
);

using f_LdrpLoadDll_WIN81 = NTSTATUS (__fastcall *)
(
	UNICODE_STRING					*	dll_path,
	LDRP_PATH_SEARCH_CONTEXT_WIN81	*	search_ctx,
	LDRP_LOAD_CONTEXT_FLAGS				Flags,
	BOOLEAN								Unknown, //set to TRUE
	LDR_DATA_TABLE_ENTRY_WIN81		**	entry_out,
	LDR_DDAG_NODE_WIN81				**	ddag_out
);

//1507-1803
using f_LdrpLoadDll_1507 = NTSTATUS (__fastcall *)
(
	UNICODE_STRING				*	dll_path,
	LDRP_PATH_SEARCH_CONTEXT	*	search_path,
	LDRP_LOAD_CONTEXT_FLAGS			Flags,
	BOOLEAN							bUnknown, //set to TRUE
	LDR_DATA_TABLE_ENTRY_WIN10	**	ldr_out
);

//1809+
using f_LdrpLoadDll = NTSTATUS (__fastcall *)
(
	UNICODE_STRING				*	dll_path, 
	LDRP_PATH_SEARCH_CONTEXT	*	search_path,
	LDRP_LOAD_CONTEXT_FLAGS			Flags,
	LDR_DATA_TABLE_ENTRY		**	ldr_out
);

using f_LdrpLoadDllInternal = VOID (__fastcall *)
(
	UNICODE_STRING				*	dll_path, 
	LDRP_PATH_SEARCH_CONTEXT	*	search_path,
	LDRP_LOAD_CONTEXT_FLAGS			Flags,
	ULONG32							Unknown0,	//set to 4
	LDR_DATA_TABLE_ENTRY_WIN10	*	Unknown1,	//set to nullptr
	LDR_DATA_TABLE_ENTRY_WIN10	*	Unknown2,	//set to nullptr
	LDR_DATA_TABLE_ENTRY_WIN10	**	ldr_out,
	NTSTATUS					*	ntRet
);

using f_LdrpLoadDllInternal_WIN11 = VOID (__fastcall *)
(
	UNICODE_STRING				*	dll_path, 
	LDRP_PATH_SEARCH_CONTEXT	*	search_path,
	LDRP_LOAD_CONTEXT_FLAGS			Flags,
	ULONG32							Unknown0,	//set to 4
	LDR_DATA_TABLE_ENTRY_WIN11	*	Unknown1,	//set to nullptr
	LDR_DATA_TABLE_ENTRY_WIN11	*	Unknown2,	//set to nullptr
	LDR_DATA_TABLE_ENTRY_WIN11	**	ldr_out,
	NTSTATUS					*	ntRet,
	ULONG							Unknown4	//set to 0
);

using f_LdrGetDllHandleEx = NTSTATUS (__stdcall *)
(
	ULONG				Flags,
	PWSTR				OptDllPath,
	PULONG				OptDllCharacteristics,
	UNICODE_STRING	*	DllName,
	PVOID			*	DllHandle
);

using f_LdrGetProcedureAddress = NTSTATUS (__stdcall *)
(
	PVOID				BaseAddress,
	ANSI_STRING		*	Name,
	ULONG				Ordinal,
	PVOID			*	ProcedureAddress
);

using f_NtQueryInformationProcess = NTSTATUS (__stdcall *)
(
	HANDLE					hTargetProc, 
	PROCESSINFOCLASS		PIC, 
	void				*	pBuffer, 
	ULONG					BufferSize, 
	ULONG				*	SizeOut
);

using f_NtQuerySystemInformation = NTSTATUS	(__stdcall *)
(
	SYSTEM_INFORMATION_CLASS		SIC, 
	void						*	pBuffer, 
	ULONG							BufferSize, 
	ULONG						*	SizeOut
);

using f_NtQueryInformationThread = NTSTATUS (__stdcall *)
(
	HANDLE				hThread, 
	THREADINFOCLASS		TIC, 
	void			*	pBuffer, 
	ULONG				BufferSize, 
	ULONG			*	SizeOut
);

using f_RtlQueueApcWow64Thread = NTSTATUS (__stdcall *)
(
	HANDLE		hThread, 
	void	*	pRoutine, 
	void	*	pArg1, 
	void	*	pArg2, 
	void	*	pArg3
);

using f_LdrGetDllPath = NTSTATUS (__stdcall *)
(
	const wchar_t	*	DllName,
	ULONG				Flags,
	wchar_t			**	PathOut,
	wchar_t			**	Unknown
);

using f_LdrpPreprocessDllName = NTSTATUS (__fastcall *)
(
	UNICODE_STRING				* DllName,
	LDRP_UNICODE_STRING_BUNDLE	* OutputDllName,
	LDR_DATA_TABLE_ENTRY		* pOptParentEntry,
	LDRP_LOAD_CONTEXT_FLAGS		* LoadContextFlags
);

using f_RtlInsertInvertedFunctionTable_WIN7 = NTSTATUS (__stdcall *)
(
	RTL_INVERTED_FUNCTION_TABLE_WIN7 *	pTable,
	void *								ImageBase,
	DWORD								SizeOfImage
);

using f_RtlInsertInvertedFunctionTable_WIN8 = NTSTATUS (__stdcall *)
(
	void *	ImageBase,
	DWORD	SizeOfImage
);

using f_RtlInsertInvertedFunctionTable = BOOL (__fastcall *)
(
	void *	ImageBase,
	DWORD	SizeOfImage
);

#ifdef _WIN64
using f_RtlAddFunctionTable = BOOL (__stdcall *)
(
	RUNTIME_FUNCTION *	FunctionTable,
	DWORD				EntryCount,
	DWORD64				BaseAddress
);
#endif

using f_LdrpHandleTlsData_WIN8 = NTSTATUS (__stdcall *)
(
	LDR_DATA_TABLE_ENTRY_WIN8 * pEntry
);

using f_LdrpHandleTlsData = NTSTATUS (__fastcall *)
(
	LDR_DATA_TABLE_ENTRY * pEntry
);

using f_LdrLockLoaderLock = NTSTATUS (__stdcall *)
(
	ULONG			Flags, 
	ULONG		*	State, 
	ULONG_PTR	*	Cookie
);

using f_LdrUnlockLoaderLock = NTSTATUS (__stdcall *)
(
	ULONG		Flags, 
	ULONG_PTR	Cookie
);

using f_LdrpDereferenceModule = NTSTATUS(__fastcall *)
(
	LDR_DATA_TABLE_ENTRY * pEntry
);

using f_memmove = VOID (__cdecl *)
(
	PVOID	UNALIGNED	Destination,
	LPCVOID	UNALIGNED	Source,
	SIZE_T				Length
);

using f_RtlZeroMemory = VOID (__stdcall *)
(
	PVOID	UNALIGNED	Destination,
	SIZE_T				Length
);

using f_RtlAllocateHeap = PVOID (__stdcall *)
(
	PVOID	HeapHandle,
	ULONG	Flags,
	SIZE_T	Size
);

using f_RtlFreeHeap = BOOLEAN (__stdcall *)
(
	PVOID	HeapHandle,
	ULONG	Flags,
	PVOID	BaseAddress
);

using f_RtlAnsiStringToUnicodeString = NTSTATUS (__stdcall *)
(
	UNICODE_STRING		*	DestinationString,
	const ANSI_STRING	*	SourceString,
	BOOLEAN					AllocateDestinationString
);

using f_RtlUnicodeStringToAnsiString = NTSTATUS (__stdcall *)
(
	ANSI_STRING				*	DestinationString,
	const UNICODE_STRING	*	SourceString,
	BOOLEAN						AllocateDestinationString
);

using f_RtlCompareString = LONG (__stdcall *)
(
	const ANSI_STRING * String1,
	const ANSI_STRING * String2,
	BOOLEAN				CaseInSensitive
);

using f_RtlCompareUnicodeString = LONG (__stdcall *)
(
	const UNICODE_STRING *	String1,
	const UNICODE_STRING *	String2,
	BOOLEAN					CaseInSensitive
);

using f_RtlRbInsertNodeEx = VOID (__stdcall *)
(
	RTL_RB_TREE			*	Tree,
	RTL_BALANCED_NODE	*	Parent,
	BOOLEAN					Right,
	RTL_BALANCED_NODE	*	Node
);

using f_RtlRbRemoveNode = VOID (__stdcall *)
(
	RTL_RB_TREE			* pTree,
	RTL_BALANCED_NODE	* pNode
);

using f_NtOpenFile = NTSTATUS (__stdcall *)
(
	HANDLE				*	hFileOut,
	ACCESS_MASK				DesiredAccess,
	OBJECT_ATTRIBUTES	*	pAtrributes,
	IO_STATUS_BLOCK		*	pIoStatusBlock,
	ULONG					ShareAccess,
	ULONG					OpenOptions
);

using f_NtReadFile = NTSTATUS (__stdcall *)
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

using f_NtSetInformationFile = NTSTATUS (__stdcall *)
(
	HANDLE						FileHandle,
	IO_STATUS_BLOCK			*	IoStatusBlock,
	PVOID						FileInformation,
	ULONG						Length,
	FILE_INFORMATION_CLASS		FileInformationClass
);

using f_NtQueryInformationFile = NTSTATUS (__stdcall *)
(
	HANDLE						FileHandle,
	IO_STATUS_BLOCK			*	pIoStatusBlock,
	PVOID						FileInformation,
	ULONG						Length,
	FILE_INFORMATION_CLASS		FileInformationClass
);

using f_NtClose = NTSTATUS (__stdcall *)
(
	HANDLE Handle
);

using f_NtAllocateVirtualMemory = NTSTATUS (__stdcall *)
(
	HANDLE			ProcessHandle,
	PVOID		*	BaseAddress,
	ULONG_PTR		ZeroBits,
	SIZE_T		*	RegionSize,
	ULONG			AllocationType,
	ULONG			Protect
);

using f_NtFreeVirtualMemory = NTSTATUS (__stdcall *)
(
	HANDLE		ProcessHandle,
	PVOID	*	BaseAddress,
	SIZE_T	*	RegionSize,
	ULONG		FreeType
);

using f_NtProtectVirtualMemory = NTSTATUS (__stdcall *)
(
	HANDLE		ProcessHandle,
	PVOID	*	BaseAddress,
	SIZE_T	*	Size,
	ULONG		NewAccess,
	ULONG	*	OldAccess
);

using f_NtCreateSection = NTSTATUS (__stdcall *)
(
	HANDLE				*	SectionHandle,
	ACCESS_MASK				DesiredAccess,
	OBJECT_ATTRIBUTES	*	ObjectAttributes,
	LARGE_INTEGER		*	MaximumSize,
	ULONG					SectionPageProtection,
	ULONG					AllocationAttributes,
	HANDLE					FileHandle
);

using f_NtMapViewOfSection = NTSTATUS (__stdcall *)
(
	HANDLE				SectionHandle,
	HANDLE				ProcessHandle,
	PVOID			*	BaseAddress,
	ULONG_PTR			ZeroBits,
	SIZE_T				CommitSize,
	LARGE_INTEGER	*	SectionOffset,
	SIZE_T			*	ViewSize,
	SECTION_INHERIT		InheritDisposition,
	ULONG				AllocationType,
	ULONG				Win32Protect
);

using f_LdrProtectMrdata = VOID (__stdcall *)
(
	BOOL bProtected
);

using f_RtlAddVectoredExceptionHandler = PVOID (__stdcall *)
(
	ULONG						FirstHandler,
	PVECTORED_EXCEPTION_HANDLER VectoredHandler
);

using f_RtlRemoveVectoredExceptionHandler = ULONG (__stdcall *)
(
	PVOID Handle
);

using f_NtDelayExecution = NTSTATUS (__stdcall *)
(
	BOOLEAN			Alertable,
	LARGE_INTEGER * DelayInterval
);

using f_LdrpModuleBaseAddressIndex	= RTL_RB_TREE *;
using f_LdrpMappingInfoIndex		= RTL_RB_TREE *;
using f_LdrpHeap					= PVOID *;
using f_LdrpInvertedFunctionTable	= RTL_INVERTED_FUNCTION_TABLE *;
using f_LdrpDefaultPath				= UNICODE_STRING *;
using f_LdrpVectorHandlerList		= RTL_VECTORED_HANDLER_LIST *;
using f_LdrpTlsList					= LIST_ENTRY *;

//ntdll.dll:
using f_RtlpUnhandledExceptionFilter	= ULONG_PTR *; //encrypted with RtlEncodePointer, points to kernel32.UnhandledExceptionFilter

//kernel32.dll:
using f_UnhandledExceptionFilter		= ULONG_PTR *; //PTOP_LEVEL_EXCEPTION_FILTER
using f_SingleHandler					= ULONG_PTR *; //encrypted with RtlEncodePointer, points to kernel32.DefaultHandler
using f_DefaultHandler					= ULONG_PTR *; //PTOP_LEVEL_EXCEPTION_FILTER

#pragma endregion

inline HINSTANCE g_hNTDLL;
inline HINSTANCE g_hKERNEL32;

#ifdef  _WIN64
inline HINSTANCE g_hNTDLL_WOW64;
inline HINSTANCE g_hKERNEL32_WOW64;
#endif