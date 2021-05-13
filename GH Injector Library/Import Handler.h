#pragma once

#include "NT Stuff.h"
#include "Symbol Parser.h"

inline ERROR_DATA					import_handler_error_data;
inline std::shared_future<DWORD>	import_handler_ret;

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

	NT_FUNC(LdrpPreprocessDllName);
	NT_FUNC(RtlInsertInvertedFunctionTable);
	NT_FUNC(LdrpHandleTlsData);

	NT_FUNC(LdrLockLoaderLock);
	NT_FUNC(LdrUnlockLoaderLock);

	NT_FUNC(memmove);
	NT_FUNC(RtlZeroMemory);
	NT_FUNC(RtlAllocateHeap);
	NT_FUNC(RtlFreeHeap);

	NT_FUNC(RtlAnsiStringToUnicodeString);

	NT_FUNC(RtlRbRemoveNode);

	NT_FUNC(NtOpenFile);
	NT_FUNC(NtReadFile);
	NT_FUNC(NtSetInformationFile);
	NT_FUNC(NtQueryInformationFile);

	NT_FUNC(NtClose);

	NT_FUNC(NtAllocateVirtualMemory);
	NT_FUNC(NtFreeVirtualMemory);
	NT_FUNC(NtProtectVirtualMemory);

	NT_FUNC(LdrpModuleBaseAddressIndex);
	NT_FUNC(LdrpMappingInfoIndex);
	NT_FUNC(LdrpHeap);
	NT_FUNC(LdrpInvertedFunctionTable);
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

	WOW64_FUNCTION_POINTER(LdrpPreprocessDllName);
	WOW64_FUNCTION_POINTER(RtlInsertInvertedFunctionTable);
	WOW64_FUNCTION_POINTER(LdrpHandleTlsData);

	WOW64_FUNCTION_POINTER(LdrLockLoaderLock);
	WOW64_FUNCTION_POINTER(LdrUnlockLoaderLock);

	WOW64_FUNCTION_POINTER(memmove);
	WOW64_FUNCTION_POINTER(RtlZeroMemory);
	WOW64_FUNCTION_POINTER(RtlAllocateHeap);
	WOW64_FUNCTION_POINTER(RtlFreeHeap);

	WOW64_FUNCTION_POINTER(RtlAnsiStringToUnicodeString);

	WOW64_FUNCTION_POINTER(RtlRbRemoveNode);

	WOW64_FUNCTION_POINTER(NtOpenFile);
	WOW64_FUNCTION_POINTER(NtReadFile);
	WOW64_FUNCTION_POINTER(NtSetInformationFile);
	WOW64_FUNCTION_POINTER(NtQueryInformationFile);

	WOW64_FUNCTION_POINTER(NtClose);

	WOW64_FUNCTION_POINTER(NtAllocateVirtualMemory);
	WOW64_FUNCTION_POINTER(NtFreeVirtualMemory);
	WOW64_FUNCTION_POINTER(NtProtectVirtualMemory);

	WOW64_FUNCTION_POINTER(LdrpModuleBaseAddressIndex);
	WOW64_FUNCTION_POINTER(LdrpMappingInfoIndex);
	WOW64_FUNCTION_POINTER(LdrpHeap);
	WOW64_FUNCTION_POINTER(LdrpInvertedFunctionTable);
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

HINSTANCE GetModuleHandleExW_WOW64(const wchar_t * lpModuleName, DWORD * PidOut = nullptr);
//Uses CreateToolHelp32Snapshot with Process32FirstW/NextW and IsWow46Process to find a wow64 process and then forwards the call to GetModuleHandleExW_WOW64 with a process handle (see next declaration).
//
//Arguments:
//		szModuleName (const wchar_t*):
///			The name of the module including the file extension.
//		PidOut (DWORD*):
///			The PID of the wow64 process that was used to determine the address of the module. This parameter can be 0.
//
//Returnvalue (HINSTANCE):
///		On success: base address of the image.
///		On failure: NULL.

HINSTANCE GetModuleHandleExW_WOW64(HANDLE hTargetProc, const wchar_t * lpModuleName);
//Uses CreateToolHelp32Snapshot and Module32First/Next to retrieve the baseaddress of an image.
//Only scans WOW64 modules of a process.
//
//Arguments:
//		hTargetProc (HANDLE):
///			A handle to the target process with either PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION.
//		szModuleName (const wchar_t*):
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
///			A handle to the target process with either PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION.
//		szModuleName (const wchar_t*):
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
//Same as other GetProcAddressExW_WOW64 overload but modulebase provided instead of modulename. For performance boost only.

#endif