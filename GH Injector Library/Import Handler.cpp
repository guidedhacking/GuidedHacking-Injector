#include "pch.h"

#include "Import Handler.h"

using namespace NATIVE;

#define S_FUNC(f) f, #f

template <typename T>
DWORD LoadNtSymbolNative(T & Function, const char * szFunction)
{
	DWORD RVA = 0;
	DWORD sym_ret = sym_ntdll_native.GetSymbolAddress(szFunction, RVA);
	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		LOG("Failed to load native function: %s\n", szFunction);

		return sym_ret;
	}

	Function = ReCa<T>(ReCa<UINT_PTR>(g_hNTDLL) + RVA);

	return INJ_ERR_SUCCESS;
}

DWORD ResolveImports(ERROR_DATA & error_data)
{
	g_hNTDLL = GetModuleHandle(TEXT("ntdll.dll"));

	HINSTANCE hK32 = GetModuleHandle(TEXT("kernel32.dll"));
	if (!hK32)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG("GetModuleHandle failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_KERNEL32_MISSING;
	}

	WIN32_FUNC_INIT(LoadLibraryExW, hK32);
	WIN32_FUNC_INIT(GetLastError, hK32);
	if (!NATIVE::pLoadLibraryExW || !NATIVE::pGetLastError)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG("GetProcAddress failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	}

	if (sym_ntdll_native_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG("Native symbol loading not finished\n");

		return INJ_ERR_SYMBOL_INIT_NOT_DONE;
	}
	
	DWORD sym_ret = sym_ntdll_native_ret.get();
	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, sym_ret);

		LOG("Native symbol loading failed: %08X\n", sym_ret);

		return INJ_ERR_SYMBOL_INIT_FAIL;
	}

	LOG("Start loading native ntdll symbols\n");

	if (LoadNtSymbolNative(S_FUNC(LdrLoadDll)))						return INJ_ERR_GET_PROC_ADDRESS_FAIL;

	if (LoadNtSymbolNative(S_FUNC(LdrGetDllHandleEx)))				return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadNtSymbolNative(S_FUNC(LdrGetProcedureAddress)))			return INJ_ERR_GET_PROC_ADDRESS_FAIL;

	if (LoadNtSymbolNative(S_FUNC(NtQueryInformationProcess)))		return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadNtSymbolNative(S_FUNC(NtQuerySystemInformation)))		return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadNtSymbolNative(S_FUNC(NtQueryInformationThread)))		return INJ_ERR_GET_PROC_ADDRESS_FAIL;

	if (LoadNtSymbolNative(NATIVE::memmove, "memmove"))				return INJ_ERR_GET_PROC_ADDRESS_FAIL; //I hate compilers
	if (LoadNtSymbolNative(S_FUNC(RtlZeroMemory)))					return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadNtSymbolNative(S_FUNC(RtlAllocateHeap)))				return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadNtSymbolNative(S_FUNC(RtlFreeHeap)))					return INJ_ERR_GET_PROC_ADDRESS_FAIL;

	if (LoadNtSymbolNative(S_FUNC(RtlAnsiStringToUnicodeString)))	return INJ_ERR_GET_PROC_ADDRESS_FAIL;

	if (LoadNtSymbolNative(S_FUNC(RtlRbRemoveNode)))				return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadNtSymbolNative(S_FUNC(NtOpenFile)))						return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadNtSymbolNative(S_FUNC(NtReadFile)))						return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadNtSymbolNative(S_FUNC(NtSetInformationFile)))			return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadNtSymbolNative(S_FUNC(NtQueryInformationFile)))			return INJ_ERR_GET_PROC_ADDRESS_FAIL;

	if (LoadNtSymbolNative(S_FUNC(NtClose)))						return INJ_ERR_GET_PROC_ADDRESS_FAIL;

	if (LoadNtSymbolNative(S_FUNC(NtAllocateVirtualMemory)))		return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadNtSymbolNative(S_FUNC(NtFreeVirtualMemory)))			return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadNtSymbolNative(S_FUNC(NtProtectVirtualMemory)))			return INJ_ERR_GET_PROC_ADDRESS_FAIL;

	if (LoadNtSymbolNative(S_FUNC(NtCreateThreadEx)))				return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	if (LoadNtSymbolNative(S_FUNC(RtlQueueApcWow64Thread)))			return INJ_ERR_GET_PROC_ADDRESS_FAIL;

	if (LoadNtSymbolNative(S_FUNC(LdrpLoadDll)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(LdrpLoadDllInternal)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolNative(S_FUNC(LdrpPreprocessDllName)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(RtlInsertInvertedFunctionTable)))	return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(LdrpHandleTlsData)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolNative(S_FUNC(LdrpAcquireLoaderLock)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(LdrpReleaseLoaderLock)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolNative(S_FUNC(LdrpModuleBaseAddressIndex)))		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(LdrpMappingInfoIndex)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(LdrpHeap)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(LdrpInvertedFunctionTable)))		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	LOG("Native ntdll symbols loaded\n");

#ifdef _WIN64
	return ResolveImports_WOW64(error_data);
#else
	return INJ_ERR_SUCCESS;
#endif
}