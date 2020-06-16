#include "pch.h"

#include "Import Handler.h"

using namespace NATIVE;

#define S_FUNC(f) f, #f

template <typename T>
DWORD LoadExportedFunction(T & Function, const char * szFunction)
{
	Function = ReCa<T>(GetProcAddress(g_hNTDLL, szFunction));
	if (!Function)
	{
		return GetLastError();
	}

	return INJ_ERR_SUCCESS;
}

template <typename T>
DWORD LoadNtSymbolNative(T & Function, const char * szFunction)
{
	DWORD RVA = 0;
	DWORD sym_ret = sym_ntdll_native.GetSymbolAddress(szFunction, RVA);
	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		return sym_ret;
	}

	Function = ReCa<T>(ReCa<UINT_PTR>(g_hNTDLL) + RVA);

	return INJ_ERR_SUCCESS;
}

DWORD ResolveImports(ERROR_DATA & error_data)
{
	g_hNTDLL = GetModuleHandle(TEXT("ntdll.dll"));

	HINSTANCE hK32 = GetModuleHandle(TEXT("kernel32.dll"));

	WIN32_FUNC_INIT(LoadLibraryExW, hK32);
	WIN32_FUNC_INIT(GetLastError, hK32);
	if (!NATIVE::pLoadLibraryExW || !NATIVE::pGetLastError) return INJ_ERR_GET_PROC_ADDRESS_FAIL;

	if (LoadExportedFunction(S_FUNC(LdrLoadDll)))					return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadExportedFunction(S_FUNC(LdrUnloadDll)))					return INJ_ERR_GET_PROC_ADDRESS_FAIL;

	if (LoadExportedFunction(S_FUNC(LdrGetDllHandleEx)))			return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadExportedFunction(S_FUNC(LdrGetProcedureAddress)))		return INJ_ERR_GET_PROC_ADDRESS_FAIL;

	if (LoadExportedFunction(S_FUNC(LdrLockLoaderLock)))			return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadExportedFunction(S_FUNC(LdrUnlockLoaderLock)))			return INJ_ERR_GET_PROC_ADDRESS_FAIL;

	if (LoadExportedFunction(S_FUNC(NtQueryInformationProcess)))	return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadExportedFunction(S_FUNC(NtQuerySystemInformation)))		return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadExportedFunction(S_FUNC(NtQueryInformationThread)))		return INJ_ERR_GET_PROC_ADDRESS_FAIL;

	if (LoadExportedFunction(S_FUNC(RtlMoveMemory)))				return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadExportedFunction(S_FUNC(RtlAllocateHeap)))				return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadExportedFunction(S_FUNC(RtlFreeHeap)))					return INJ_ERR_GET_PROC_ADDRESS_FAIL;

	if (LoadExportedFunction(S_FUNC(RtlAnsiStringToUnicodeString))) return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadExportedFunction(S_FUNC(RtlUnicodeStringToAnsiString))) return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadExportedFunction(S_FUNC(RtlInitUnicodeString)))			return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadExportedFunction(S_FUNC(RtlHashUnicodeString)))			return INJ_ERR_GET_PROC_ADDRESS_FAIL;

	if (LoadExportedFunction(S_FUNC(RtlRbInsertNodeEx)))			return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadExportedFunction(S_FUNC(RtlRbRemoveNode)))				return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	
	if (LoadExportedFunction(S_FUNC(NtOpenFile)))					return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadExportedFunction(S_FUNC(NtReadFile)))					return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadExportedFunction(S_FUNC(NtSetInformationFile)))			return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadExportedFunction(S_FUNC(NtQueryInformationFile)))		return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadExportedFunction(S_FUNC(NtCreateSection)))				return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadExportedFunction(S_FUNC(NtMapViewOfSection)))			return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadExportedFunction(S_FUNC(NtUnmapViewOfSection)))			return INJ_ERR_GET_PROC_ADDRESS_FAIL;

	if (LoadExportedFunction(S_FUNC(NtClose)))						return INJ_ERR_GET_PROC_ADDRESS_FAIL;

	if (LoadExportedFunction(S_FUNC(NtAllocateVirtualMemory)))		return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadExportedFunction(S_FUNC(NtFreeVirtualMemory)))			return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadExportedFunction(S_FUNC(NtProtectVirtualMemory)))		return INJ_ERR_GET_PROC_ADDRESS_FAIL;

	if (LoadExportedFunction(S_FUNC(RtlGetSystemTimePrecise)))		return INJ_ERR_GET_PROC_ADDRESS_FAIL;

	if (LoadExportedFunction(S_FUNC(NtCreateThreadEx)))				return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadExportedFunction(S_FUNC(RtlQueueApcWow64Thread)))		return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	
	if (sym_ntdll_native_ret.wait_for(std::chrono::milliseconds(100)) != std::future_status::ready)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return INJ_ERR_SYMBOL_INIT_NOT_DONE;
	}
	
	DWORD sym_ret = sym_ntdll_native_ret.get();
	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, sym_ret);

		return INJ_ERR_SYMBOL_INIT_FAIL;
	}

	if (LoadNtSymbolNative(S_FUNC(LdrpLoadDll)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolNative(S_FUNC(LdrpPreprocessDllName)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(RtlInsertInvertedFunctionTable)))	return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(LdrpHandleTlsData)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolNative(S_FUNC(LdrpModuleBaseAddressIndex)))		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(LdrpMappingInfoIndex)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(LdrpHashTable)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(LdrpHeap)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	
#ifdef _WIN64
	return ResolveImports_WOW64(error_data);
#else
	return INJ_ERR_SUCCESS;
#endif
}