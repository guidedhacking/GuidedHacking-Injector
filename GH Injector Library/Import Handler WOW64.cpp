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

	PROCESS_INFORMATION pi{ 0 };
	STARTUPINFOW		si{ 0 };
	si.cb			= sizeof(si);
	si.dwFlags		= STARTF_USESHOWWINDOW;
	si.wShowWindow	= SW_HIDE;

	SECURITY_ATTRIBUTES sa{ 0 };
	sa.nLength			= sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle	= TRUE;

	HANDLE hEventStart = CreateEventEx(&sa, nullptr, CREATE_EVENT_MANUAL_RESET, EVENT_ALL_ACCESS);
	if (!hEventStart)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG("   CreateEventEx failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_CREATE_EVENT_FAILED;
	}

	HANDLE hEventEnd = CreateEventEx(&sa, nullptr, CREATE_EVENT_MANUAL_RESET, EVENT_ALL_ACCESS);
	if (!hEventEnd)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG("   CreateEventEx failed: %08X\n", error_data.AdvErrorCode);

		CloseHandle(hEventStart);

		return INJ_ERR_CREATE_EVENT_FAILED;
	}

	wchar_t hEventStart_string[9]{ 0 };
	_ultow_s(MDWD(hEventStart), hEventStart_string, 0x10);

	wchar_t hEventEnd_string[9]{ 0 };
	_ultow_s(MDWD(hEventEnd), hEventEnd_string, 0x10);

	wchar_t RootPath[MAX_PATH * 2]{ 0 };
	StringCbCopyW(RootPath, sizeof(RootPath), g_RootPathW.c_str());
	StringCbCatW(RootPath, sizeof(RootPath), SM_EXE_FILENAME86);

	wchar_t cmdLine[MAX_PATH]{ 0 };
	StringCbCatW(cmdLine, sizeof(cmdLine), L"\"" SM_EXE_FILENAME86 "\" " ID_WOW64 " ");
	StringCbCatW(cmdLine, sizeof(cmdLine), hEventStart_string);
	StringCbCatW(cmdLine, sizeof(cmdLine), L" ");
	StringCbCatW(cmdLine, sizeof(cmdLine), hEventEnd_string);

	if (!CreateProcessW(RootPath, cmdLine, nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG("   CreateProcessW failed: %08X\n", error_data.AdvErrorCode);

		CloseHandle(hEventStart);
		CloseHandle(hEventEnd);

		return INJ_ERR_CREATE_PROCESS_FAILED;
	}

	DWORD dwWaitRet = WaitForSingleObject(hEventStart, 1000);
	if (dwWaitRet != WAIT_OBJECT_0)
	{
		DWORD err_ret = INJ_ERR_WAIT_FAILED;

		if (dwWaitRet == WAIT_FAILED)
		{
			INIT_ERROR_DATA(error_data, GetLastError());
		}
		else
		{
			INIT_ERROR_DATA(error_data, dwWaitRet);
			err_ret = INJ_ERR_WAIT_TIMEOUT;
		}

		LOG("   WaitForSingleObject failed: %08X\n", error_data.AdvErrorCode);

		SetEvent(hEventEnd);

		CloseHandle(hEventStart);
		CloseHandle(hEventEnd);

		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);

		return err_ret;
	}

	auto wow64_pid = GetProcessId(pi.hProcess);
	LOG("   Successfully spawned wow64 dummy process: %08X (%d)\n", wow64_pid, wow64_pid);

	g_hNTDLL_WOW64 = GetModuleHandleExW_WOW64(pi.hProcess, L"ntdll.dll");
	auto hKernel32_WOW64 = GetModuleHandleExW_WOW64(pi.hProcess, L"kernel32.dll");

	if (!g_hNTDLL_WOW64 || !hKernel32_WOW64)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		if (!g_hNTDLL_WOW64)
		{
			LOG("   Failed to get WOW64 ntdll.dll\n");
		}

		if (!hKernel32_WOW64)
		{
			LOG("   Failed to get WOW64 kernel32.dll\n");
		}

		SetEvent(hEventEnd);

		CloseHandle(hEventStart);
		CloseHandle(hEventEnd);

		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);

		return INJ_ERR_WOW64_NTDLL_MISSING;
	}

	LOG("   WOW64 kernel32.dll loaded at %08X\n", MDWD(hKernel32_WOW64));

	bool b_lle	= GetProcAddressEx_WOW64(pi.hProcess, hKernel32_WOW64, "LoadLibraryExW", WOW64::LoadLibraryExW_WOW64);
	bool b_gle	= GetProcAddressEx_WOW64(pi.hProcess, hKernel32_WOW64, "GetLastError", WOW64::GetLastError_WOW64);

	SetEvent(hEventEnd);

	CloseHandle(hEventStart);
	CloseHandle(hEventEnd);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	if (!b_lle || !b_gle)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		if (!b_lle)
		{
			LOG("   Failed to resolve WOW64 address of LoadLibrarExW\n");
		}

		if (!b_gle)
		{
			LOG("   Failed to resolve WOW64 address of GetLastError\n");
		}

		return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	}

	LOG("    LoadLibraryExW = %08X\n", WOW64::LoadLibraryExW_WOW64);
	LOG("    GetLastError   = %08X\n", WOW64::GetLastError_WOW64);

	LOG("   Waiting for WOW64 symbol parser to finish initialization\n");

	while (sym_ntdll_wow64_ret.wait_for(std::chrono::milliseconds(100)) != std::future_status::ready);

	LOG("   WOW64 ntdll.dll loaded at %08X\n", MDWD(g_hNTDLL_WOW64));

	DWORD sym_ret = sym_ntdll_wow64_ret.get();
	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, sym_ret);

		LOG("   WOW64 symbol loading failed: %08X\n", sym_ret);

		return INJ_ERR_SYMBOL_INIT_FAIL;
	}

	LOG("   Start loading WOW64 ntdll symbols\n");

	if (LoadNtSymbolWOW64(S_FUNC(LdrLoadDll)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(LdrUnloadDll)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(LdrpLoadDll)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolWOW64(S_FUNC(LdrGetDllHandleEx)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(LdrGetProcedureAddress)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolWOW64(WOW64::memmove_WOW64, "memmove"))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(RtlZeroMemory)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(RtlAllocateHeap)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(RtlFreeHeap)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolWOW64(S_FUNC(RtlAnsiStringToUnicodeString)))		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;


	if (LoadNtSymbolWOW64(S_FUNC(NtOpenFile)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(NtReadFile)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(NtSetInformationFile)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(NtQueryInformationFile)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolWOW64(S_FUNC(NtClose)))								return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	
	if (LoadNtSymbolWOW64(S_FUNC(NtAllocateVirtualMemory)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(NtFreeVirtualMemory)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(NtProtectVirtualMemory)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolWOW64(S_FUNC(NtCreateSection)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(NtMapViewOfSection)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolWOW64(S_FUNC(RtlInsertInvertedFunctionTable)))		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(LdrpHandleTlsData)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolWOW64(S_FUNC(LdrLockLoaderLock)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(LdrUnlockLoaderLock)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolWOW64(S_FUNC(RtlAddVectoredExceptionHandler)))		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(RtlRemoveVectoredExceptionHandler)))	return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadNtSymbolWOW64(S_FUNC(LdrpHeap)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadNtSymbolWOW64(S_FUNC(LdrpInvertedFunctionTable)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (IsWin7OrGreater() && !IsWin8OrGreater())
	{
		if (LoadNtSymbolWOW64(S_FUNC(LdrpDefaultPath)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	}

	if (IsWin8OrGreater())
	{
		if (LoadNtSymbolWOW64(S_FUNC(RtlRbRemoveNode)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		if (LoadNtSymbolWOW64(S_FUNC(LdrpModuleBaseAddressIndex)))		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		if (LoadNtSymbolWOW64(S_FUNC(LdrpMappingInfoIndex)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	}

	if (IsWin81OrGreater())
	{
		if (LoadNtSymbolWOW64(S_FUNC(LdrProtectMrdata)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	}

	if (IsWin10OrGreater())
	{
		if (LoadNtSymbolWOW64(S_FUNC(LdrpPreprocessDllName)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		if (LoadNtSymbolWOW64(S_FUNC(LdrpLoadDllInternal)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	}

	LOG("   WOW64 ntdll symbols loaded\n");

	return INJ_ERR_SUCCESS;
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
	while (bRet)
	{
		if (ME32.modBaseAddr && !_wcsicmp(ME32.szModule, lpModuleName) && (ME32.modBaseAddr < (BYTE *)0x7FFFF000))
		{
			BYTE header[0x1000];
			if (!ReadProcessMemory(hTargetProc, ME32.modBaseAddr, header, sizeof(header), nullptr))
			{
				bRet = Module32NextW(hSnap, &ME32);

				continue;
			}

			IMAGE_DOS_HEADER	* pDos	= ReCa<IMAGE_DOS_HEADER *>(header);
			IMAGE_NT_HEADERS32	* pNT	= ReCa<IMAGE_NT_HEADERS32 *>(header + pDos->e_lfanew);

			if (pNT->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
			{
				bRet = Module32NextW(hSnap, &ME32);

				continue;
			}

			break;
		}

		bRet = Module32NextW(hSnap, &ME32);
	}

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