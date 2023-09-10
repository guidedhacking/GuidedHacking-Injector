/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

#pragma once

#include "NT Funcs.h"
#include "Symbol Parser.h"
#include "Tools.h"

inline HANDLE g_hRunningEvent		= nullptr;
inline HANDLE g_hInterruptEvent		= nullptr;
inline HANDLE g_hInterruptedEvent	= nullptr;
inline HANDLE g_hInterruptImport	= nullptr;

inline ERROR_DATA					import_handler_error_data;
inline std::shared_future<DWORD>	import_handler_ret;

#ifdef _WIN64
inline ERROR_DATA					import_handler_wow64_error_data;
inline std::shared_future<DWORD>	import_handler_wow64_ret;
#endif

//Macros for import definitions

#define NT_FUNC(func) inline f_##func func = nullptr
#define NT_FUNC_LOCAL(func) f_##func func
#define NT_FUNC_CONSTRUCTOR_INIT(func) this->func = NATIVE::func

#define WIN32_FUNC(func) inline decltype(func) * p##func = nullptr
#define WIN32_FUNC_LOCAL(func) decltype(func) * p##func
#define WIN32_FUNC_INIT(func, lib) NATIVE::p##func = ReCa<decltype(func) *>(GetProcAddress(lib, #func));
#define WIN32_FUNC_CONSTRUCTOR_INIT(func) this->p##func = NATIVE::p##func

#define K32_FUNC(func) inline f_##func func = nullptr
#define K32_FUNC_LOCAL(func) f_##func func
#define K32_FUNC_CONSTRUCTOR_INIT(func) this->func = NATIVE::func

#define WOW64_FUNCTION_POINTER(func) inline DWORD func##_WOW64 = 0
#define WOW64_FUNCTION_POINTER_LOCAL(func) DWORD func = 0
#define WOW64_FUNC_CONSTRUCTOR_INIT(func) this->func = WOW64::func##_WOW64

#define IDX_NTDLL		0
#define IDX_KERNEL32	1

//Command line codes for "GH Injector SM - XX.exe"

#define ID_SWHEX	"0" //use for SetWindowsHookEx
#define ID_WOW64	"1" //use for wow64 addresses
#define ID_KC		"2" //use for KernelCallbackTable

namespace NATIVE
{
	WIN32_FUNC(LoadLibraryA);
	WIN32_FUNC(LoadLibraryW);
	WIN32_FUNC(LoadLibraryExA);
	WIN32_FUNC(LoadLibraryExW);

	WIN32_FUNC(GetModuleHandleA);
	WIN32_FUNC(GetModuleHandleW);
	WIN32_FUNC(GetModuleHandleExA);
	WIN32_FUNC(GetModuleHandleExW);

	WIN32_FUNC(GetModuleFileNameA);
	WIN32_FUNC(GetModuleFileNameW);

	WIN32_FUNC(GetProcAddress);

	WIN32_FUNC(DisableThreadLibraryCalls);
	WIN32_FUNC(FreeLibrary);
	WIN32_FUNC(FreeLibraryAndExitThread);
	WIN32_FUNC(ExitThread);

	WIN32_FUNC(GetLastError);

	NT_FUNC(LdrLoadDll);
	NT_FUNC(LdrUnloadDll);

	NT_FUNC(LdrpLoadDll);
	NT_FUNC(LdrpLoadDllInternal);

	NT_FUNC(LdrGetDllHandleEx);
	NT_FUNC(LdrGetProcedureAddress);

	NT_FUNC(NtCreateThreadEx);
	NT_FUNC(RtlQueueApcWow64Thread);

	NT_FUNC(NtQueryInformationProcess);
	NT_FUNC(NtQuerySystemInformation);
	NT_FUNC(NtQueryInformationThread);

	NT_FUNC(LdrGetDllPath);
	NT_FUNC(LdrpPreprocessDllName);
	NT_FUNC(RtlInsertInvertedFunctionTable);
	NT_FUNC(LdrpHandleTlsData);

	NT_FUNC(LdrLockLoaderLock);
	NT_FUNC(LdrUnlockLoaderLock);

	NT_FUNC(LdrpDereferenceModule);

	NT_FUNC(memmove);
	NT_FUNC(RtlZeroMemory);
	NT_FUNC(RtlAllocateHeap);
	NT_FUNC(RtlFreeHeap);

	NT_FUNC(RtlAnsiStringToUnicodeString);
	NT_FUNC(RtlUnicodeStringToAnsiString);
	NT_FUNC(RtlCompareUnicodeString);
	NT_FUNC(RtlCompareString);

	NT_FUNC(RtlRbInsertNodeEx);
	NT_FUNC(RtlRbRemoveNode);

	NT_FUNC(NtOpenFile);
	NT_FUNC(NtReadFile);
	NT_FUNC(NtSetInformationFile);
	NT_FUNC(NtQueryInformationFile);

	NT_FUNC(NtClose);

	NT_FUNC(NtAllocateVirtualMemory);
	NT_FUNC(NtFreeVirtualMemory);
	NT_FUNC(NtProtectVirtualMemory);

	NT_FUNC(NtCreateSection);
	NT_FUNC(NtMapViewOfSection);

	NT_FUNC(LdrProtectMrdata);

	NT_FUNC(RtlAddVectoredExceptionHandler);
	NT_FUNC(RtlRemoveVectoredExceptionHandler);

	NT_FUNC(NtDelayExecution);

	NT_FUNC(LdrpModuleBaseAddressIndex);
	NT_FUNC(LdrpMappingInfoIndex);
	NT_FUNC(LdrpHeap);
	NT_FUNC(LdrpInvertedFunctionTable);
	NT_FUNC(LdrpDefaultPath);
	NT_FUNC(LdrpVectorHandlerList);
	NT_FUNC(LdrpTlsList);

	NT_FUNC(RtlpUnhandledExceptionFilter);
	K32_FUNC(UnhandledExceptionFilter);
	K32_FUNC(SingleHandler);
	K32_FUNC(DefaultHandler);

#ifdef _WIN64
	NT_FUNC(RtlAddFunctionTable);
#endif
}

DWORD ResolveImports(ERROR_DATA & error_data);
//Resolves the addresses of all the required functions (see the NATIVE namespace) using the ntdll.pdb file.
//
//Arguments:
//		error_data (ERROR_DATA &):
///			A reference to an ERROR_DATA structure which will contain information if the function fails.
//
//Returnvalue (DWORD):
///		On success: INJ_ERR_SUCCESS (0)
///		On failure: An error code. See Error.h.

#ifdef _WIN64

namespace WOW64
{
	WOW64_FUNCTION_POINTER(LoadLibraryExW);
	WOW64_FUNCTION_POINTER(GetLastError);
		
	WOW64_FUNCTION_POINTER(LdrLoadDll);
	WOW64_FUNCTION_POINTER(LdrUnloadDll);

	WOW64_FUNCTION_POINTER(LdrpLoadDll);
	WOW64_FUNCTION_POINTER(LdrpLoadDllInternal);

	WOW64_FUNCTION_POINTER(LdrGetDllHandleEx);
	WOW64_FUNCTION_POINTER(LdrGetProcedureAddress);

	WOW64_FUNCTION_POINTER(NtCreateThreadEx);
	WOW64_FUNCTION_POINTER(RtlQueueApcWow64Thread);

	WOW64_FUNCTION_POINTER(NtQueryInformationProcess);
	WOW64_FUNCTION_POINTER(NtQuerySystemInformation);
	WOW64_FUNCTION_POINTER(NtQueryInformationThread);

	WOW64_FUNCTION_POINTER(LdrGetDllPath);
	WOW64_FUNCTION_POINTER(LdrpPreprocessDllName);
	WOW64_FUNCTION_POINTER(RtlInsertInvertedFunctionTable);
	WOW64_FUNCTION_POINTER(LdrpHandleTlsData);

	WOW64_FUNCTION_POINTER(LdrLockLoaderLock);
	WOW64_FUNCTION_POINTER(LdrUnlockLoaderLock);

	WOW64_FUNCTION_POINTER(LdrpDereferenceModule);

	WOW64_FUNCTION_POINTER(memmove);
	WOW64_FUNCTION_POINTER(RtlZeroMemory);
	WOW64_FUNCTION_POINTER(RtlAllocateHeap);
	WOW64_FUNCTION_POINTER(RtlFreeHeap);

	WOW64_FUNCTION_POINTER(RtlAnsiStringToUnicodeString);
	WOW64_FUNCTION_POINTER(RtlUnicodeStringToAnsiString);
	WOW64_FUNCTION_POINTER(RtlCompareUnicodeString);
	WOW64_FUNCTION_POINTER(RtlCompareString);

	WOW64_FUNCTION_POINTER(RtlRbRemoveNode);

	WOW64_FUNCTION_POINTER(NtOpenFile);
	WOW64_FUNCTION_POINTER(NtReadFile);
	WOW64_FUNCTION_POINTER(NtSetInformationFile);
	WOW64_FUNCTION_POINTER(NtQueryInformationFile);

	WOW64_FUNCTION_POINTER(NtClose);

	WOW64_FUNCTION_POINTER(NtAllocateVirtualMemory);
	WOW64_FUNCTION_POINTER(NtFreeVirtualMemory);
	WOW64_FUNCTION_POINTER(NtProtectVirtualMemory);

	WOW64_FUNCTION_POINTER(NtCreateSection);
	WOW64_FUNCTION_POINTER(NtMapViewOfSection);

	WOW64_FUNCTION_POINTER(LdrProtectMrdata);

	WOW64_FUNCTION_POINTER(RtlAddVectoredExceptionHandler);
	WOW64_FUNCTION_POINTER(RtlRemoveVectoredExceptionHandler);

	WOW64_FUNCTION_POINTER(NtDelayExecution);

	WOW64_FUNCTION_POINTER(LdrpModuleBaseAddressIndex);
	WOW64_FUNCTION_POINTER(LdrpMappingInfoIndex);
	WOW64_FUNCTION_POINTER(LdrpHeap);
	WOW64_FUNCTION_POINTER(LdrpInvertedFunctionTable);
	WOW64_FUNCTION_POINTER(LdrpDefaultPath);
	WOW64_FUNCTION_POINTER(LdrpVectorHandlerList);
	WOW64_FUNCTION_POINTER(LdrpTlsList);

	WOW64_FUNCTION_POINTER(RtlpUnhandledExceptionFilter);
	WOW64_FUNCTION_POINTER(UnhandledExceptionFilter);
	WOW64_FUNCTION_POINTER(SingleHandler);
	WOW64_FUNCTION_POINTER(DefaultHandler);
}

DWORD ResolveImports_WOW64(ERROR_DATA & error_data);
//Resolves the addresses of all the required wow64 functions (see the WOW64 namespace) using the wntdll.pdb file.
//
//Arguments:
//		error_data (ERROR_DATA &):
///			A reference to an ERROR_DATA structure which will contain information if the function fails.
//
//Returnvalue (DWORD):
///		On success: INJ_ERR_SUCCESS (0)
///		On failure: An error code. See Error.h.

HINSTANCE GetModuleHandleExW_WOW64(HANDLE hTargetProc, const wchar_t * lpModuleName);
//Uses CreateToolHelp32Snapshot and Module32First/Next to retrieve the baseaddress of an image.
//Only scans WOW64 modules of a process.
//
//Arguments:
//		hTargetProc (HANDLE):
///			A handle to the target process with PROCESS_VM_READ and PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION.
//		szModuleName (const wchar_t *):
///			The name of the module including the file extension.
//
//Returnvalue (HINSTANCE):
///		On success: base address of the image.
///		On failure: NULL.

bool GetProcAddressExW_WOW64(HANDLE hTargetProc, const wchar_t * szModuleName, const char * szProcName, DWORD &pOut);
//A function which tries to get the address of a function by parsing the export directory of the specified module.
//(WOW64 compatible version of GetProcAddressEx)
//
//Arguments:
//		hTargetProc (HANDLE):
///			A handle to the target process with PROCESS_VM_READ and PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION.
//		szModuleName (const wchar_t *):
///			The name of the module including the file extension.
//		szProcName (const char *):
///			The name of the function as an ansi string.
//		pOut (DWORD &):
///			A reference to a wow64 pointer that (on success) will contain the pointer to the function in the specified target process.
//
//Returnvalue (bool):
///		true:	pOut now contains the address of the function.
///		false:	something went wrong.

bool GetProcAddressEx_WOW64(HANDLE hTargetProc, HINSTANCE hModule, const char * szProcName, DWORD &pOut);
//Same as other GetProcAddressExW_WOW64 overload but modulebase provided instead of modulename. For performance boost only.

#endif

//For internal usage only:
#ifdef __cplusplus
extern "C"
{
	__declspec(dllexport) inline extern bool g_LibraryState = false;
}
#endif