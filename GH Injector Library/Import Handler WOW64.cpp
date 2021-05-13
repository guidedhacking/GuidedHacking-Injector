#include "pch.h"

#ifdef _WIN64

#include "Import Handler.h"

#ifdef UNICODE
#undef MODULEENTRY32
#undef Module32First
#undef Module32Next
#endif

using namespace WOW64;

#define S_FUNC(f) f##_WOW64, #f

template <typename T>
DWORD LoadNtSymbolWOW64(T & Function, const char * szFunction)
{
	DWORD RVA = 0;
	DWORD sym_ret = sym_ntdll_wow64.GetSymbolAddress(szFunction, RVA);
	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		LOG("    Failed to load WOW64 function: %s\n", szFunction);

		return 0;
	}

	Function = (T)(ReCa<UINT_PTR>(g_hNTDLL_WOW64) + RVA);

	return INJ_ERR_SUCCESS;
}

DWORD ResolveImports_WOW64(ERROR_DATA & error_data)
{
	LOG("  ResolveImports_WOW64 called\n");

	g_hNTDLL_WOW64 = GetModuleHandleExW_WOW64(L"ntdll.dll");
	if (!g_hNTDLL_WOW64)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG("   Failed to get WOW64 ntdll.dll\n");

		return INJ_ERR_WOW64_NTDLL_MISSING;
	}

	DWORD WOW64_dummy_process_id = 0;
	auto hKernel32_WOW64 = GetModuleHandleExW_WOW64(L"kernel32.dll", &WOW64_dummy_process_id);
	if (!hKernel32_WOW64)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG("   Failed to get WOW64 kernel32.dll\n");

		return INJ_ERR_WOW64_KERNEL32_MISSING;
	}

	HANDLE hWOW64_dummy_process = OpenProcess(PROCESS_VM_READ, FALSE, WOW64_dummy_process_id);
	if (!hWOW64_dummy_process)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG("   Failed to attach to WOW64 process\n");

		return INJ_ERR_OPEN_WOW64_PROCESS;
	}

	if (!GetProcAddressEx_WOW64(hWOW64_dummy_process, hKernel32_WOW64, "LoadLibraryExW", WOW64::LoadLibraryExW_WOW64) || !GetProcAddressEx_WOW64(hWOW64_dummy_process, hKernel32_WOW64, "GetLastError", WOW64::GetLastError_WOW64))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG("   Missing WOW64 specific imports\n");

		CloseHandle(hWOW64_dummy_process);

		return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	}

	CloseHandle(hWOW64_dummy_process);

	LOG("   Waiting for wow64 symbol parser to finish initialization\n");

	while (sym_ntdll_wow64_ret.wait_for(std::chrono::milliseconds(100)) != std::future_status::ready);

	DWORD sym_ret = sym_ntdll_wow64_ret.get();
	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, sym_ret);

		LOG("   WOW64 symbol loading failed: %08X\n", sym_ret);

		return INJ_ERR_SYMBOL_INIT_FAIL;
	}

	LOG("   Start loading WOW64 ntdll symbols\n");

	if (LoadNtSymbolWOW64(S_FUNC(LdrLoadDll)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(LdrUnloadDll)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolWOW64(S_FUNC(LdrpLoadDll)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(LdrpLoadDllInternal)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolWOW64(S_FUNC(LdrGetDllHandleEx)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(LdrGetProcedureAddress)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolWOW64(WOW64::memmove_WOW64, "memmove"))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(RtlZeroMemory)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(RtlAllocateHeap)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(RtlFreeHeap)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolWOW64(S_FUNC(RtlAnsiStringToUnicodeString)))	return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolWOW64(S_FUNC(RtlRbRemoveNode)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolWOW64(S_FUNC(NtOpenFile)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(NtReadFile)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(NtSetInformationFile)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(NtQueryInformationFile)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolWOW64(S_FUNC(NtClose)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	
	if (LoadNtSymbolWOW64(S_FUNC(NtAllocateVirtualMemory)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(NtFreeVirtualMemory)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(NtProtectVirtualMemory)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolWOW64(S_FUNC(LdrpPreprocessDllName)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(RtlInsertInvertedFunctionTable)))	return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(LdrpHandleTlsData)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolWOW64(S_FUNC(LdrLockLoaderLock)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(LdrUnlockLoaderLock)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolWOW64(S_FUNC(LdrpModuleBaseAddressIndex)))		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(LdrpMappingInfoIndex)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(LdrpHeap)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(LdrpInvertedFunctionTable)))		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	LOG("   WOW64 ntdll symbols loaded\n");

	return INJ_ERR_SUCCESS;
}

HINSTANCE GetModuleHandleExW_WOW64(const wchar_t * szModuleName, DWORD * PidOut)
{
	HINSTANCE hRet = NULL;

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnap == INVALID_HANDLE_VALUE)
	{
		while (GetLastError() == ERROR_BAD_LENGTH)
		{
			hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

			if (hSnap != INVALID_HANDLE_VALUE)
			{
				break;
			}
		}

		Sleep(5);
	}

	if (hSnap == INVALID_HANDLE_VALUE || !hSnap)
	{
		return NULL;
	}

	PROCESSENTRY32W PE32{ 0 };
	PE32.dwSize = sizeof(PROCESSENTRY32W);

	BOOL bRet = Process32FirstW(hSnap, &PE32);

	for (; bRet; bRet = Process32NextW(hSnap, &PE32))
	{
		HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, PE32.th32ProcessID);
		if (!hProc)
		{
			continue;
		}

		BOOL bWOW64 = FALSE;
		if (!IsWow64Process(hProc, &bWOW64) || !bWOW64)
		{
			CloseHandle(hProc);

			continue;
		}

		hRet = GetModuleHandleExW_WOW64(hProc, szModuleName);

		CloseHandle(hProc);

		if (hRet)
		{
			if (PidOut)
			{
				*PidOut = PE32.th32ProcessID;
			}

			break;
		}
	}

	CloseHandle(hSnap);

	return hRet;
}

HINSTANCE GetModuleHandleExW_WOW64(HANDLE hTargetProc, const wchar_t * lpModuleName)
{
	MODULEENTRY32W ME32{ 0 };
	ME32.dwSize = sizeof(ME32);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, GetProcessId(hTargetProc));
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		while (GetLastError() == ERROR_BAD_LENGTH)
		{
			hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, GetProcessId(hTargetProc));

			if (hSnap != INVALID_HANDLE_VALUE)
			{
				break;
			}
		}

		Sleep(5);
	}

	if (hSnap == INVALID_HANDLE_VALUE || !hSnap)
	{
		return NULL;
	}

	BOOL bRet = Module32FirstW(hSnap, &ME32);
	do
	{
		if (!_wcsicmp(ME32.szModule, lpModuleName) && (ME32.modBaseAddr < (BYTE *)0x7FFFF000))
		{
			break;
		}

		bRet = Module32NextW(hSnap, &ME32);
	} while (bRet);

	CloseHandle(hSnap);

	if (!bRet)
	{
		return NULL;
	}

	return ME32.hModule;
}

bool GetProcAddressExW_WOW64(HANDLE hTargetProc, const wchar_t * szModuleName, const char * szProcName, DWORD &pOut)
{
	return GetProcAddressEx_WOW64(hTargetProc, GetModuleHandleExW_WOW64(hTargetProc, szModuleName), szProcName, pOut);
}

bool GetProcAddressEx_WOW64(HANDLE hTargetProc, HINSTANCE hModule, const char * szProcName, DWORD &pOut)
{
	BYTE * modBase = ReCa<BYTE*>(hModule);

	if (!modBase)
	{
		return false;
	}

	BYTE * pBuffer = new BYTE[0x1000];
	if (!ReadProcessMemory(hTargetProc, modBase, pBuffer, 0x1000, nullptr))
	{
		delete[] pBuffer;

		return false;
	}

	auto * pNT = ReCa<IMAGE_NT_HEADERS32*>(ReCa<IMAGE_DOS_HEADER*>(pBuffer)->e_lfanew + pBuffer);
	auto * pDir = &pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	auto ExportSize = pDir->Size;
	auto DirRVA		= pDir->VirtualAddress;

	if (!ExportSize)
	{
		delete[] pBuffer;

		return false;
	}

	BYTE * pExpDirBuffer = new BYTE[ExportSize];
	auto * pExportDir = ReCa<IMAGE_EXPORT_DIRECTORY*>(pExpDirBuffer);
	if (!ReadProcessMemory(hTargetProc, modBase + DirRVA, pExpDirBuffer, ExportSize, nullptr))
	{
		delete[] pExpDirBuffer;
		delete[] pBuffer;

		return false;
	}

	BYTE * pBase = pExpDirBuffer - DirRVA;

	auto Forward = [&](DWORD FuncRVA, DWORD &pForwarded) -> bool
	{
		char pFullExport[MAX_PATH]{ 0 };
		size_t len_out = 0;

		HRESULT hr = StringCchLengthA(ReCa<char*>(pBase + FuncRVA), sizeof(pFullExport), &len_out);
		if (FAILED(hr) || !len_out)
		{
			return false;
		}

		StringCchCopyA(pFullExport, len_out, ReCa<char*>(pBase + FuncRVA));
		
		char * pFuncName = strchr(pFullExport, '.');
		*pFuncName++ = '\0';
		if (*pFuncName == '#')
		{
			pFuncName = ReCa<char*>(LOWORD(atoi(++pFuncName)));
		}

		wchar_t ModNameW[MAX_PATH]{ 0 };
		size_t SizeOut = 0;

		if (mbstowcs_s(&SizeOut, ModNameW, pFullExport, MAX_PATH))
		{
			return GetProcAddressExW_WOW64(hTargetProc, ModNameW, pFuncName, pForwarded);
		}
		else
		{
			return false;
		}
	};

	if (ReCa<ULONG_PTR>(szProcName) <= MAXWORD)
	{
		WORD Base		= LOWORD(pExportDir->Base - 1);
		WORD Ordinal	= LOWORD(szProcName) - Base;
		DWORD FuncRVA	= ReCa<DWORD*>(pBase + pExportDir->AddressOfFunctions)[Ordinal];

		delete[] pExpDirBuffer;
		delete[] pBuffer;

		if (FuncRVA >= DirRVA && FuncRVA < DirRVA + ExportSize)
		{
			return Forward(FuncRVA, pOut);
		}
			
		pOut = MDWD(modBase) + FuncRVA;
		
		return true;
	}

	DWORD max		= pExportDir->NumberOfNames - 1;
	DWORD min		= 0;
	DWORD FuncRVA	= 0;

	while (min <= max)
	{
		DWORD mid = (min + max) / 2;

		DWORD CurrNameRVA	= ReCa<DWORD*>(pBase + pExportDir->AddressOfNames)[mid];
		char * szName		= ReCa<char*>(pBase + CurrNameRVA);

		int cmp = strcmp(szName, szProcName);
		if (cmp < 0)
		{
			min = mid + 1;
		}
		else if (cmp > 0)
		{
			max = mid - 1;
		}
		else 
		{
			WORD Ordinal = ReCa<WORD*>(pBase + pExportDir->AddressOfNameOrdinals)[mid];
			FuncRVA = ReCa<DWORD*>(pBase + pExportDir->AddressOfFunctions)[Ordinal];

			break;
		}
	}
	
	delete[] pExpDirBuffer;
	delete[] pBuffer;

	if (!FuncRVA)
	{
		return false;
	}

	if (FuncRVA >= DirRVA && FuncRVA < DirRVA + ExportSize)
	{
		return Forward(FuncRVA, pOut);
	}

	pOut = MDWD(modBase) + FuncRVA;

	return true;
}

#endif