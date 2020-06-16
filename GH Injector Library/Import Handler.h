#pragma once

#include "NT Stuff.h"
#include "Symbol Parser.h"

#define NT_FUNC(func) inline f_##func func = nullptr
#define NT_FUNC_LOCAL(func) f_##func func
#define NT_FUNC_CONSTRUCTOR_INIT(func) this->func = NATIVE::func

#define WIN32_FUNC(func) inline decltype(func)* p##func = nullptr
#define WIN32_FUNC_LOCAL(func) decltype(func)* p##func
#define WIN32_FUNC_INIT(func, lib) NATIVE::p##func = ReCa<decltype(func)*>(GetProcAddress(lib, #func));
#define WIN32_FUNC_CONSTRUCTOR_INIT(func) this->p##func = NATIVE::p##func

#define WOW64_FUNCTION_POINTER(func) inline DWORD func##_WOW64 = 0
#define WOW64_FUNCTION_POINTER_LOCAL(func) DWORD func
#define WOW64_FUNC_CONSTRUCTOR_INIT(func) this->func = WOW64::func##_WOW64

namespace NATIVE
{
	WIN32_FUNC(LoadLibraryExW);
	WIN32_FUNC(GetLastError);

	NT_FUNC(LdrLoadDll);
	NT_FUNC(LdrpLoadDll);
	NT_FUNC(LdrUnloadDll);

	NT_FUNC(LdrGetDllHandleEx);
	NT_FUNC(LdrGetProcedureAddress);

	NT_FUNC(LdrLockLoaderLock);
	NT_FUNC(LdrUnlockLoaderLock);

	NT_FUNC(NtCreateThreadEx);
	NT_FUNC(RtlQueueApcWow64Thread);

	NT_FUNC(NtQueryInformationProcess);
	NT_FUNC(NtQuerySystemInformation);
	NT_FUNC(NtQueryInformationThread);

	NT_FUNC(LdrpPreprocessDllName);
	NT_FUNC(RtlInsertInvertedFunctionTable);
	NT_FUNC(LdrpHandleTlsData);

	NT_FUNC(RtlMoveMemory);
	NT_FUNC(RtlAllocateHeap);
	NT_FUNC(RtlFreeHeap);

	NT_FUNC(RtlAnsiStringToUnicodeString);
	NT_FUNC(RtlUnicodeStringToAnsiString);
	NT_FUNC(RtlInitUnicodeString);
	NT_FUNC(RtlHashUnicodeString);

	NT_FUNC(RtlRbInsertNodeEx);
	NT_FUNC(RtlRbRemoveNode);

	NT_FUNC(NtOpenFile);
	NT_FUNC(NtReadFile);
	NT_FUNC(NtSetInformationFile);
	NT_FUNC(NtQueryInformationFile);
	NT_FUNC(NtCreateSection);
	NT_FUNC(NtMapViewOfSection);
	NT_FUNC(NtUnmapViewOfSection);

	NT_FUNC(NtClose);

	NT_FUNC(NtAllocateVirtualMemory);
	NT_FUNC(NtFreeVirtualMemory);
	NT_FUNC(NtProtectVirtualMemory);

	NT_FUNC(RtlGetSystemTimePrecise);

	NT_FUNC(LdrpModuleBaseAddressIndex);
	NT_FUNC(LdrpMappingInfoIndex);
	NT_FUNC(LdrpHashTable);
	NT_FUNC(LdrpHeap);
}

DWORD ResolveImports(ERROR_DATA & error_data);

#ifdef _WIN64

namespace WOW64
{
	WOW64_FUNCTION_POINTER(LoadLibraryExW);
	WOW64_FUNCTION_POINTER(GetLastError);
		
	WOW64_FUNCTION_POINTER(LdrLoadDll);
	WOW64_FUNCTION_POINTER(LdrpLoadDll);
	WOW64_FUNCTION_POINTER(LdrUnloadDll);

	WOW64_FUNCTION_POINTER(LdrGetDllHandleEx);
	WOW64_FUNCTION_POINTER(LdrGetProcedureAddress);

	WOW64_FUNCTION_POINTER(LdrLockLoaderLock);
	WOW64_FUNCTION_POINTER(LdrUnlockLoaderLock);

	WOW64_FUNCTION_POINTER(NtCreateThreadEx);
	WOW64_FUNCTION_POINTER(RtlQueueApcWow64Thread);

	WOW64_FUNCTION_POINTER(NtQueryInformationProcess);
	WOW64_FUNCTION_POINTER(NtQuerySystemInformation);
	WOW64_FUNCTION_POINTER(NtQueryInformationThread);

	WOW64_FUNCTION_POINTER(LdrpPreprocessDllName);
	WOW64_FUNCTION_POINTER(RtlInsertInvertedFunctionTable);
	WOW64_FUNCTION_POINTER(LdrpHandleTlsData);

	WOW64_FUNCTION_POINTER(RtlMoveMemory);
	WOW64_FUNCTION_POINTER(RtlAllocateHeap);
	WOW64_FUNCTION_POINTER(RtlFreeHeap);

	WOW64_FUNCTION_POINTER(RtlAnsiStringToUnicodeString);
	WOW64_FUNCTION_POINTER(RtlUnicodeStringToAnsiString);
	WOW64_FUNCTION_POINTER(RtlInitUnicodeString);
	WOW64_FUNCTION_POINTER(RtlHashUnicodeString);

	WOW64_FUNCTION_POINTER(RtlRbInsertNodeEx);
	WOW64_FUNCTION_POINTER(RtlRbRemoveNode);

	WOW64_FUNCTION_POINTER(NtOpenFile);
	WOW64_FUNCTION_POINTER(NtReadFile);
	WOW64_FUNCTION_POINTER(NtSetInformationFile);
	WOW64_FUNCTION_POINTER(NtQueryInformationFile);
	WOW64_FUNCTION_POINTER(NtCreateSection);
	WOW64_FUNCTION_POINTER(NtMapViewOfSection);
	WOW64_FUNCTION_POINTER(NtUnmapViewOfSection);

	WOW64_FUNCTION_POINTER(NtClose);

	WOW64_FUNCTION_POINTER(NtAllocateVirtualMemory);
	WOW64_FUNCTION_POINTER(NtFreeVirtualMemory);
	WOW64_FUNCTION_POINTER(NtProtectVirtualMemory);

	WOW64_FUNCTION_POINTER(RtlGetSystemTimePrecise);

	WOW64_FUNCTION_POINTER(LdrpModuleBaseAddressIndex);
	WOW64_FUNCTION_POINTER(LdrpMappingInfoIndex);
	WOW64_FUNCTION_POINTER(LdrpHashTable);
	WOW64_FUNCTION_POINTER(LdrpHeap);
}

DWORD ResolveImports_WOW64(ERROR_DATA & error_data);

HINSTANCE GetModuleHandleEx_WOW64(HANDLE hTargetProc, const TCHAR * lpModuleName);
//Uses CreateToolHelp32Snapshot and Module32First/Next to retrieve the baseaddress of an image.
//Only scans WOW64 modules of a process.
//
//Arguments:
//		hTargetProc (HANDLE):
///			A handle to the target process with either PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION.
//		szModuleName (const TCHAR*):
///			The name of the module including the file extension.
//
//Returnvalue (HINSTANCE):
///		On success: base address of the image.
///		On failure: NULL.

HINSTANCE GetModuleHandleExA_WOW64(HANDLE hTargetProc, const char		* lpModuleName);
HINSTANCE GetModuleHandleExW_WOW64(HANDLE hTargetProc, const wchar_t	* lpModuleName);

bool GetProcAddressEx_WOW64(HANDLE hTargetProc, const TCHAR * szModuleName, const char * szProcName, DWORD &pOut);
//A function which tries to get the address of a function by parsing the export directory of the specified module.
//(WOW64 compatible version of GetProcAddressEx)
//
//Arguments:
//		hTargetProc (HANDLE):
///			A handle to the target process with either PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION.
//		szModuleName (const TCHAR*):
///			The name of the module including the file extension.
//		szProcName (const char*):
///			The name of the function as an ansi string.
//		pOut (DWORD&):
///			A reference to a wow64 pointer that (on success) will contain the pointer to the function in the specified target process.
//
//Returnvalue (bool):
///		true:	pOut now contains the address of the function.
///		false:	something went wrong.

bool GetProcAddressEx_WOW64(HANDLE hTargetProc, HINSTANCE hModule, const char * szProcName, DWORD &pOut);
//Same as other GetProcAddressEx_WOW64 overload but modulebase provided instead of modulename. For performance boost only.

#endif