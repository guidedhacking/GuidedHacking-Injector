#include "pch.h"

#include "Import Handler.h"

using namespace NATIVE;

#define S_FUNC(f) NATIVE::f, #f

template <typename T>
DWORD LoadSymbolNative(T & Function, const char * szFunction, int index = IDX_NTDLL)
{
	DWORD RVA = 0;
	DWORD sym_ret = 0;
	T out = nullptr;

	sym_ret = sym_parser.GetSymbolAddress(szFunction, RVA);

	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		LOG(1, "Failed to load native function: %s\n", szFunction);

		return 0;
	}

	switch (index)
	{
		case IDX_NTDLL:
			out = ReCa<T>(ReCa<UINT_PTR>(g_hNTDLL) + RVA);
			break;

		case IDX_KERNEL32:
			out = ReCa<T>(ReCa<UINT_PTR>(g_hKERNEL32) + RVA);
			break;

		default:
			LOG(1, "Invalid symbol index specified. Failed to load native function: %s\n", szFunction);
			return 0;
	}

	Function = out;

	return INJ_ERR_SUCCESS;
}

DWORD ResolveImports(ERROR_DATA & error_data)
{
	LOG(1, "ResolveImports called\n");

	DWORD err = ERROR_SUCCESS;
	if (!GetOSVersion(&err))
	{
		INIT_ERROR_DATA(error_data, err);

		LOG(1, "Failed to determine Windows version\n");

		return INJ_ERR_WINDOWS_VERSION;
	}

	if (GetOSVersion() < g_Win7)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "This Windows version is not supported\n");

		return INJ_ERR_WINDOWS_TOO_OLD;
	}

	g_hNTDLL	= GetModuleHandle(TEXT("ntdll.dll"));
	g_hKERNEL32 = GetModuleHandle(TEXT("kernel32.dll"));

	LOG(1, "ntdll.dll    loaded at %p\n", g_hNTDLL);
	LOG(1, "kernel32.dll loaded at %p\n", g_hKERNEL32);
	LOG(1, "OSVersion = %d\nOSBuildVersion = %d\n", GetOSVersion(), GetOSBuildVersion());

	HINSTANCE hK32 = GetModuleHandle(TEXT("kernel32.dll"));
	if (!hK32)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "GetModuleHandle failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_KERNEL32_MISSING;
	}

	WIN32_FUNC_INIT(LoadLibraryA, hK32);
	WIN32_FUNC_INIT(LoadLibraryW, hK32);
	WIN32_FUNC_INIT(LoadLibraryExA, hK32);
	WIN32_FUNC_INIT(LoadLibraryExW, hK32);

	WIN32_FUNC_INIT(GetModuleHandleA, hK32);
	WIN32_FUNC_INIT(GetModuleHandleW, hK32);
	WIN32_FUNC_INIT(GetModuleHandleExA, hK32);
	WIN32_FUNC_INIT(GetModuleHandleExW, hK32);

	WIN32_FUNC_INIT(GetModuleFileNameA, hK32);
	WIN32_FUNC_INIT(GetModuleFileNameW, hK32);

	WIN32_FUNC_INIT(GetProcAddress, hK32);

	WIN32_FUNC_INIT(DisableThreadLibraryCalls, hK32);
	WIN32_FUNC_INIT(FreeLibrary, hK32);
	WIN32_FUNC_INIT(FreeLibraryAndExitThread, hK32);
	WIN32_FUNC_INIT(ExitThread, hK32);

	WIN32_FUNC_INIT(GetLastError, hK32);

	if (!NATIVE::pLoadLibraryExW || !NATIVE::pGetLastError)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "GetProcAddress failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	}

	LOG(1, "Waiting for native symbol parser to finish initialization\n");

	while (sym_ntdll_native_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
	{
		if (WaitForSingleObject(g_hInterruptImport, 10) == WAIT_OBJECT_0)
		{
			return INJ_ERR_IMPORT_INTERRUPT;
		}
	}
	
	DWORD sym_ret = sym_ntdll_native_ret.get();
	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, sym_ret);

		LOG(1, "Native symbol loading failed: %08X\n", sym_ret);

		return INJ_ERR_SYMBOL_LOAD_FAIL;
	}

	sym_ret = sym_parser.Initialize(&sym_ntdll_native);
	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, sym_ret);

		LOG(1, "Native symbol parsing failed: %08X\n", sym_ret);

		return INJ_ERR_SYMBOL_PARSE_FAIL;
	}

	LOG(1, "LoadLibraryExW: %p\n", &LoadLibraryExW);

	LOG(1, "Start loading native ntdll symbols\n");

	if (LoadSymbolNative(S_FUNC(LdrLoadDll)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(LdrUnloadDll)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(LdrpLoadDll)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(LdrGetDllHandleEx)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(LdrGetProcedureAddress)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(NtQueryInformationProcess)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(NtQuerySystemInformation)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(NtQueryInformationThread)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(memmove)))								return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED; //I hate compilers
	if (LoadSymbolNative(S_FUNC(RtlZeroMemory)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(RtlAllocateHeap)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(RtlFreeHeap)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(RtlAnsiStringToUnicodeString)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED; 
	if (LoadSymbolNative(S_FUNC(RtlUnicodeStringToAnsiString)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(RtlCompareUnicodeString)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(RtlCompareString)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	
	if (LoadSymbolNative(S_FUNC(NtOpenFile)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(NtReadFile)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(NtSetInformationFile)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(NtQueryInformationFile)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(NtClose)))								return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(NtAllocateVirtualMemory)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(NtFreeVirtualMemory)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(NtProtectVirtualMemory)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(NtCreateSection)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(NtMapViewOfSection)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(NtCreateThreadEx)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(RtlQueueApcWow64Thread)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(RtlInsertInvertedFunctionTable)))		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(LdrpHandleTlsData)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(LdrLockLoaderLock)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(LdrUnlockLoaderLock)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(RtlAddVectoredExceptionHandler)))		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(RtlRemoveVectoredExceptionHandler)))	return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(NtDelayExecution)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(LdrpHeap)))								return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(LdrpVectorHandlerList)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(LdrpTlsList)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	
	if (IsWin11OrGreater() && GetOSBuildVersion() >= g_Win11_22H2)
	{
		if (LoadSymbolNative(LdrpInvertedFunctionTable, "LdrpInvertedFunctionTables")) return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	}
	else
	{
		if (LoadSymbolNative(S_FUNC(LdrpInvertedFunctionTable))) return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	}

	if (GetOSVersion() == g_Win7)
	{
		if (LoadSymbolNative(S_FUNC(LdrpDefaultPath)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		if (LoadSymbolNative(S_FUNC(RtlpUnhandledExceptionFilter)))		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	}

	if (IsWin8OrGreater())
	{
		if (LoadSymbolNative(S_FUNC(LdrGetDllPath)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

		if (LoadSymbolNative(S_FUNC(RtlRbRemoveNode)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		if (LoadSymbolNative(S_FUNC(LdrpModuleBaseAddressIndex)))		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		if (LoadSymbolNative(S_FUNC(LdrpMappingInfoIndex)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	}

	if (IsWin81OrGreater())
	{
		if (LoadSymbolNative(S_FUNC(LdrProtectMrdata)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	}

	if (IsWin10OrGreater())
	{
		if (LoadSymbolNative(S_FUNC(LdrpPreprocessDllName)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		if (LoadSymbolNative(S_FUNC(LdrpLoadDllInternal)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		if (LoadSymbolNative(S_FUNC(LdrpDereferenceModule)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	}

#ifdef _WIN64
	if (LoadSymbolNative(S_FUNC(RtlAddFunctionTable)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
#endif

	sym_ntdll_native.Cleanup();

	if (GetOSVersion() == g_Win7)
	{
		while (sym_kernel32_native_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
		{
			if (WaitForSingleObject(g_hInterruptImport, 10) == WAIT_OBJECT_0)
			{
				return INJ_ERR_IMPORT_INTERRUPT;
			}
		}
	
		sym_ret = sym_kernel32_native_ret.get();
		if (sym_ret != SYMBOL_ERR_SUCCESS)
		{
			INIT_ERROR_DATA(error_data, sym_ret);

			LOG(1, "Native symbol loading failed: %08X\n", sym_ret);

			return INJ_ERR_SYMBOL_LOAD_FAIL;
		}

		sym_ret = sym_parser.Initialize(&sym_kernel32_native);
		if (sym_ret != SYMBOL_ERR_SUCCESS)
		{
			INIT_ERROR_DATA(error_data, sym_ret);

			LOG(1, "Native symbol parsing failed: %08X\n", sym_ret);

			return INJ_ERR_SYMBOL_PARSE_FAIL;
		}

		if (LoadSymbolNative(S_FUNC(UnhandledExceptionFilter),	IDX_KERNEL32))	return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		if (LoadSymbolNative(S_FUNC(SingleHandler),				IDX_KERNEL32))	return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		if (LoadSymbolNative(S_FUNC(DefaultHandler),			IDX_KERNEL32))	return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

		sym_kernel32_native.Cleanup();

		LOG(1, "Native kernel32 symbols loaded\n");
	}

	LOG(1, "Native ntdll symbols loaded\n");

#ifndef _WIN64
	sym_parser.Cleanup();

	g_LibraryState = true; //on x64 ResolveImports_WOW64 will update g_LibraryState and free parser resources
#endif

	return INJ_ERR_SUCCESS;
}