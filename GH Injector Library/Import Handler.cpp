#include "pch.h"

#include "Import Handler.h"

bool IsWin7OrGreater()
{
	return (GetOSVersion() >= g_Win7);
}

bool IsWin8OrGreater()
{
	return (GetOSVersion() >= g_Win8);
}

bool IsWin81OrGreater()
{
	return (GetOSVersion() >= g_Win81);
}

bool IsWin10OrGreater()
{
	return (GetOSVersion() >= g_Win10);
}

bool IsWin11OrGreater()
{
	return (GetOSVersion() >= g_Win10 && GetOSBuildVersion() >= g_Win11_21H2);
}

DWORD GetOSVersion(DWORD * error_code)
{
	if (g_OSVersion != 0)
	{
		return g_OSVersion;
	}

#ifdef _WIN64
	PEB * pPEB = ReCa<PEB *>(__readgsqword(0x60));
#else
	PEB * pPEB = ReCa<PEB *>(__readfsdword(0x30));
#endif

	if (!pPEB)
	{
		if (error_code)
		{
			*error_code = INJ_ERR_CANT_GET_PEB;
		}

		return 0;
	}

	DWORD v_hi = pPEB->OSMajorVersion;
	DWORD v_lo = pPEB->OSMinorVersion;

	for (; v_lo >= 10; v_lo /= 10);

	g_OSVersion = v_hi * 10 + v_lo;

	g_OSBuildNumber = pPEB->OSBuildNumber;

	return g_OSVersion;
}

DWORD GetOSBuildVersion()
{
	return g_OSBuildNumber;
}

using namespace NATIVE;

#define S_FUNC(f) f, #f

template <typename T>
DWORD LoadNtSymbolNative(T & Function, const char * szFunction)
{
	DWORD RVA = 0;
	DWORD sym_ret = sym_ntdll_native.GetSymbolAddress(szFunction, RVA);
	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		LOG("    Failed to load native function: %s\n", szFunction);

		return sym_ret;
	}

	Function = ReCa<T>(ReCa<UINT_PTR>(g_hNTDLL) + RVA);

	return INJ_ERR_SUCCESS;
}

DWORD ResolveImports(ERROR_DATA & error_data)
{
	LOG("  ResolveImports called\n");

	DWORD err = ERROR_SUCCESS;
	if (!GetOSVersion(&err))
	{
		INIT_ERROR_DATA(error_data, err);

		LOG("   Failed to determine Windows version\n");

		return INJ_ERR_WINDOWS_VERSION;
	}

	if (GetOSVersion() < g_Win7)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG("   This Windows version is not supported\n");

		return INJ_ERR_WINDOWS_TOO_OLD;
	}

	g_hNTDLL = GetModuleHandle(TEXT("ntdll.dll"));

	printf("   ntdll.dll loaded at %p\n", g_hNTDLL);
	printf("   OSVersion = %d\n   OSBuildVersion = %d\n", GetOSVersion(), GetOSBuildVersion());

	HINSTANCE hK32 = GetModuleHandle(TEXT("kernel32.dll"));
	if (!hK32)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG("   GetModuleHandle failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_KERNEL32_MISSING;
	}

	WIN32_FUNC_INIT(LoadLibraryExW, hK32);
	WIN32_FUNC_INIT(GetLastError, hK32);

	if (!NATIVE::pLoadLibraryExW || !NATIVE::pGetLastError)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG("   GetProcAddress failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	}

	LOG("   Waiting for native symbol parser to finish initialization\n");

	while (sym_ntdll_native_ret.wait_for(std::chrono::milliseconds(100)) != std::future_status::ready);
	
	DWORD sym_ret = sym_ntdll_native_ret.get();
	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, sym_ret);

		LOG("   Native symbol loading failed: %08X\n", sym_ret);

		return INJ_ERR_SYMBOL_INIT_FAIL;
	}

	printf("LoadLibrary: %p\n", LoadLibraryExW);

	LOG("   Start loading native ntdll symbols\n");

	if (LoadNtSymbolNative(S_FUNC(LdrLoadDll)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(LdrUnloadDll)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolNative(S_FUNC(LdrpLoadDll)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolNative(S_FUNC(LdrGetDllHandleEx)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(LdrGetProcedureAddress)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolNative(S_FUNC(NtQueryInformationProcess)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(NtQuerySystemInformation)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(NtQueryInformationThread)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolNative(NATIVE::memmove, "memmove"))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED; //I hate compilers
	if (LoadNtSymbolNative(S_FUNC(RtlZeroMemory)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(RtlAllocateHeap)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(RtlFreeHeap)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolNative(S_FUNC(RtlAnsiStringToUnicodeString)))		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolNative(S_FUNC(NtOpenFile)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(NtReadFile)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(NtSetInformationFile)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(NtQueryInformationFile)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolNative(S_FUNC(NtClose)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolNative(S_FUNC(NtAllocateVirtualMemory)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(NtFreeVirtualMemory)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(NtProtectVirtualMemory)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolNative(S_FUNC(NtCreateSection)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(NtMapViewOfSection)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolNative(S_FUNC(NtCreateThreadEx)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(RtlQueueApcWow64Thread)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolNative(S_FUNC(RtlInsertInvertedFunctionTable)))		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(LdrpHandleTlsData)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolNative(S_FUNC(LdrLockLoaderLock)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(LdrUnlockLoaderLock)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolNative(S_FUNC(RtlAddVectoredExceptionHandler)))		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(RtlRemoveVectoredExceptionHandler)))	return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolNative(S_FUNC(LdrpHeap)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolNative(S_FUNC(LdrpInvertedFunctionTable)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (IsWin7OrGreater() && !IsWin8OrGreater())
	{
		if (LoadNtSymbolNative(S_FUNC(LdrpDefaultPath)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	}

	if (IsWin8OrGreater())
	{
		if (LoadNtSymbolNative(S_FUNC(RtlRbRemoveNode)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		if (LoadNtSymbolNative(S_FUNC(LdrpModuleBaseAddressIndex)))		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		if (LoadNtSymbolNative(S_FUNC(LdrpMappingInfoIndex)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	}

	if (IsWin81OrGreater())
	{
		if (LoadNtSymbolNative(S_FUNC(LdrProtectMrdata)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	}

	if (IsWin10OrGreater())
	{
		if (LoadNtSymbolNative(S_FUNC(LdrpPreprocessDllName)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		if (LoadNtSymbolNative(S_FUNC(LdrpLoadDllInternal)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	}

#ifdef _WIN64
	if (LoadNtSymbolNative(NATIVE::RtlAddFunctionTable, "RtlAddFunctionTable"))	return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
#endif

	LOG("   Native ntdll symbols loaded\n");

#ifdef _WIN64
	return ResolveImports_WOW64(error_data);
#else
	return INJ_ERR_SUCCESS;
#endif
}