#include "pch.h"

#ifdef _WIN64

#include "Import Handler.h"

#ifdef UNICODE
#undef MODULEENTRY32
#undef Module32First
#undef Module32Next
#endif

using namespace WOW64;

bool InitializeWow64NtDll()
{
	HANDLE hSnapProc = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	while (hSnapProc == INVALID_HANDLE_VALUE && GetLastError() == ERROR_BAD_LENGTH)
	{
		hSnapProc = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	}

	if (!hSnapProc || hSnapProc == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	PROCESSENTRY32 PE32{ 0 };
	PE32.dwSize = sizeof(PROCESSENTRY32);

	BOOL bRetProc = Process32First(hSnapProc, &PE32);

	for (; bRetProc; bRetProc = Process32Next(hSnapProc, &PE32))
	{
		HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, PE32.th32ProcessID);
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

		CloseHandle(hProc);

		HANDLE hSnapMod = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, PE32.th32ProcessID);

		while (hSnapMod == INVALID_HANDLE_VALUE && GetLastError() == ERROR_BAD_LENGTH)
		{
			hSnapMod = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, PE32.th32ProcessID);
		}

		if (hSnapMod == INVALID_HANDLE_VALUE)
		{
			continue;
		}

		MODULEENTRY32 ME32{ 0 };
		ME32.dwSize = sizeof(MODULEENTRY32);

		BOOL bRetMod = Module32First(hSnapMod, &ME32);

		for (; bRetMod != 0; bRetMod = Module32Next(hSnapMod, &ME32))
		{
			if (!_stricmp(ME32.szModule, "NTDLL.dll") && ME32.hModule && ReCa<UINT_PTR>(ME32.hModule) < 0x7FFFFFFF)
			{
				g_hNTDLL_WOW64 = ME32.hModule;

				CloseHandle(hSnapMod);
				CloseHandle(hSnapProc);

				return true;
			}
		}
	}

	CloseHandle(hSnapProc);

	return false;
}

#define S_FUNC(f) f##_WOW64, #f

template <typename T>
DWORD LoadNtSymbolWOW64(T & Function, const char * szFunction)
{
	DWORD RVA = 0;
	DWORD sym_ret = sym_ntdll_wow64.GetSymbolAddress(szFunction, RVA);
	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		LOG("Failed to load WOW64 function: %s\n", szFunction);

		return 0;
	}

	Function = (T)(ReCa<UINT_PTR>(g_hNTDLL_WOW64) + RVA);

	return INJ_ERR_SUCCESS;
}

DWORD ResolveImports_WOW64(ERROR_DATA & error_data)
{
	if (!InitializeWow64NtDll())
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG("Failed to get WOW64 ntdll\n");

		return INJ_ERR_WOW64_NTDLL_MISSING;
	}

	if (sym_ntdll_wow64_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG("WOW64 symbol loading not finished\n");

		return INJ_ERR_SYMBOL_INIT_NOT_DONE;
	}

	DWORD sym_ret = sym_ntdll_wow64_ret.get();
	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, sym_ret);

		LOG("WOW64 symbol loading failed: %08X\n", sym_ret);

		return INJ_ERR_SYMBOL_INIT_FAIL;
	}

	LOG("Start loading WOW64 ntdll symbols\n");

	if (LoadNtSymbolWOW64(S_FUNC(LdrLoadDll)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
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

	if (LoadNtSymbolWOW64(S_FUNC(LdrpAcquireLoaderLock)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(LdrpReleaseLoaderLock)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolWOW64(S_FUNC(LdrpModuleBaseAddressIndex)))		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(LdrpMappingInfoIndex)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(LdrpHeap)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(LdrpInvertedFunctionTable)))		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	LOG("WOW64 ntdll symbols loaded\n");

	return INJ_ERR_SUCCESS;
}

HINSTANCE GetModuleHandleEx_WOW64(HANDLE hTargetProc, const TCHAR * szModuleName)
{
#ifdef UNICODE
	return GetModuleHandleExW_WOW64(hTargetProc, szModuleName);
#else
	return GetModuleHandleExA_WOW64(hTargetProc, szModuleName);
#endif
}

HINSTANCE GetModuleHandleExA_WOW64(HANDLE hTargetProc, const char * lpModuleName)
{
	MODULEENTRY32 ME32{ 0 };
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
	}

	if (hSnap == INVALID_HANDLE_VALUE || !hSnap)
	{
		return NULL;
	}

	BOOL bRet = Module32First(hSnap, &ME32);
	do
	{
		if (!_stricmp(ME32.szModule, lpModuleName) && (ME32.modBaseAddr < (BYTE *)0x7FFFF000))
		{
			break;
		}

		bRet = Module32Next(hSnap, &ME32);
	} while (bRet);

	CloseHandle(hSnap);

	if (!bRet)
	{
		return NULL;
	}

	return ME32.hModule;
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

bool GetProcAddressEx_WOW64(HANDLE hTargetProc, const TCHAR * szModuleName, const char * szProcName, DWORD &pOut)
{
	return GetProcAddressEx_WOW64(hTargetProc, GetModuleHandleEx_WOW64(hTargetProc, szModuleName), szProcName, pOut);
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

#ifdef UNICODE

		wchar_t ModNameW[MAX_PATH]{ 0 };
		size_t SizeOut = 0;

		if (mbstowcs_s(&SizeOut, ModNameW, pFullExport, MAX_PATH))
		{
			return GetProcAddressEx_WOW64(hTargetProc, ModNameW, pFuncName, pForwarded);
		}
		else
		{
			return false;
		}

#else
		return GetProcAddressEx_WOW64(hTargetProc, pFullExport, pFuncName, pForwarded);
#endif
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