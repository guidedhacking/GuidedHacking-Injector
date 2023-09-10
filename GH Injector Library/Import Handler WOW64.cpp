/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

#include "pch.h"

#ifdef _WIN64

#include "Import Handler.h"

#ifdef UNICODE
#undef MODULEENTRY32
#undef Module32First
#undef Module32Next
#endif

using namespace WOW64;

#define S_FUNC(f) WOW64::f##_WOW64, #f

template <typename T>
DWORD LoadSymbolWOW64(T & Function, const char * szFunction, int index = IDX_NTDLL)
{
	DWORD RVA		= 0;
	DWORD sym_ret	= 0;
	DWORD out		= 0;

	sym_ret = sym_parser.GetSymbolAddress(szFunction, RVA);

	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		LOG(1, "Failed to load WOW64 function: %s\n", szFunction);

		return 0;
	}

	switch (index)
	{
		case IDX_NTDLL:			
			out	= MDWD(g_hNTDLL_WOW64) + RVA;
			break;

		case IDX_KERNEL32:
			out	= MDWD(g_hKERNEL32_WOW64) + RVA;
			break;

		default:
			LOG(1, "Invalid symbol index specified. Failed to load WOW64 function: %s\n", szFunction);
			return 0;
	}

	Function = (T)out;

	return INJ_ERR_SUCCESS;
}

DWORD ResolveImports_WOW64(ERROR_DATA & error_data)
{
	LOG(1, "ResolveImports_WOW64 called\n");

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

		LOG(1, "CreateEventEx failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_CREATE_EVENT_FAILED;
	}

	HANDLE hEventEnd = CreateEventEx(&sa, nullptr, CREATE_EVENT_MANUAL_RESET, EVENT_ALL_ACCESS);
	if (!hEventEnd)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "CreateEventEx failed: %08X\n", error_data.AdvErrorCode);

		CloseHandle(hEventStart);

		return INJ_ERR_CREATE_EVENT_FAILED;
	}

	wchar_t hEventStart_string[9]{ 0 };
	_ultow_s(MDWD(hEventStart), hEventStart_string, 0x10);

	wchar_t hEventEnd_string[9]{ 0 };
	_ultow_s(MDWD(hEventEnd), hEventEnd_string, 0x10);

	std::wstring SM_Path = g_RootPathW + SM_EXE_FILENAME86;

	if (!FileExistsW(SM_Path))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "GH Injector SM - x86.exe is missing\n");

		return INJ_ERR_SM86_EXE_MISSING;
	}

	std::wstring CmdLine = L"\"" SM_EXE_FILENAME86 "\" " ID_WOW64 " ";
	CmdLine += hEventStart_string;
	CmdLine += L" ";
	CmdLine += hEventEnd_string;

	wchar_t szCmdLine[MAX_PATH]{ 0 };
	CmdLine.copy(szCmdLine, CmdLine.length()); //CmdLine will not exceed MAX_PATH characters (46 characters max)

	if (!CreateProcessW(SM_Path.c_str(), szCmdLine, nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "CreateProcessW failed: %08X\n", error_data.AdvErrorCode);

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

		LOG(1, "WaitForSingleObject failed: %08X\n", error_data.AdvErrorCode);

		SetEvent(hEventEnd);

		CloseHandle(hEventStart);
		CloseHandle(hEventEnd);

		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);

		return err_ret;
	}

	auto wow64_pid = GetProcessId(pi.hProcess);
	LOG(1, "Successfully spawned wow64 dummy process: %08X (%d)\n", wow64_pid, wow64_pid);

	g_hNTDLL_WOW64		= GetModuleHandleExW_WOW64(pi.hProcess, L"ntdll.dll");
	g_hKERNEL32_WOW64	= GetModuleHandleExW_WOW64(pi.hProcess, L"kernel32.dll");

	if (!g_hNTDLL_WOW64 || !g_hKERNEL32_WOW64)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		if (!g_hNTDLL_WOW64)
		{
			LOG(1, "Failed to get WOW64 ntdll.dll\n");
		}

		if (!g_hKERNEL32_WOW64)
		{
			LOG(1, "Failed to get WOW64 kernel32.dll\n");
		}

		SetEvent(hEventEnd);

		CloseHandle(hEventStart);
		CloseHandle(hEventEnd);

		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);

		return INJ_ERR_WOW64_NTDLL_MISSING;
	}

	LOG(1, "WOW64 kernel32.dll loaded at %08X\n", MDWD(g_hKERNEL32_WOW64));

	bool b_lle	= GetProcAddressEx_WOW64(pi.hProcess, g_hKERNEL32_WOW64, "LoadLibraryExW", WOW64::LoadLibraryExW_WOW64);
	bool b_gle	= GetProcAddressEx_WOW64(pi.hProcess, g_hKERNEL32_WOW64, "GetLastError", WOW64::GetLastError_WOW64);

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
			LOG(1, "Failed to resolve WOW64 address of LoadLibrarExW\n");
		}

		if (!b_gle)
		{
			LOG(1, "Failed to resolve WOW64 address of GetLastError\n");
		}

		return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	}

	LOG(1, "LoadLibraryExW = %08X\n", WOW64::LoadLibraryExW_WOW64);
	LOG(1, "GetLastError   = %08X\n", WOW64::GetLastError_WOW64);

	LOG(1, "Waiting for WOW64 symbol parser to finish initialization\n");

	while (sym_ntdll_wow64_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
	{
		if (WaitForSingleObject(g_hInterruptImport, 10) == WAIT_OBJECT_0)
		{
			return INJ_ERR_IMPORT_INTERRUPT;
		}
	}

	LOG(1, "WOW64 ntdll.dll loaded at %08X\n", MDWD(g_hNTDLL_WOW64));

	DWORD sym_ret = sym_ntdll_wow64_ret.get();
	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, sym_ret);

		LOG(1, "WOW64 symbol loading failed: %08X\n", sym_ret);

		return INJ_ERR_SYMBOL_LOAD_FAIL;
	}

	while (!import_handler_ret.valid())
	{
		if (WaitForSingleObject(g_hInterruptImport, 10) == WAIT_OBJECT_0)
		{
			return INJ_ERR_IMPORT_INTERRUPT;
		}
	}

	while (import_handler_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
	{
		if (WaitForSingleObject(g_hInterruptImport, 10) == WAIT_OBJECT_0)
		{
			return INJ_ERR_IMPORT_INTERRUPT;
		}
	}

	sym_ret = sym_parser.Initialize(&sym_ntdll_wow64);
	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, sym_ret);

		LOG(1, "WOW64 symbol parsing failed: %08X\n", sym_ret);

		return INJ_ERR_SYMBOL_PARSE_FAIL;
	}

	LOG(1, "Start loading WOW64 ntdll symbols\n");

	if (LoadSymbolWOW64(S_FUNC(LdrLoadDll)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolWOW64(S_FUNC(LdrUnloadDll)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolWOW64(S_FUNC(LdrpLoadDll)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolWOW64(S_FUNC(LdrGetDllHandleEx)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolWOW64(S_FUNC(LdrGetProcedureAddress)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolWOW64(S_FUNC(memmove)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolWOW64(S_FUNC(RtlZeroMemory)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolWOW64(S_FUNC(RtlAllocateHeap)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolWOW64(S_FUNC(RtlFreeHeap)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	
	if (LoadSymbolWOW64(S_FUNC(RtlAnsiStringToUnicodeString)))		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolWOW64(S_FUNC(RtlUnicodeStringToAnsiString)))		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolWOW64(S_FUNC(RtlCompareUnicodeString)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolWOW64(S_FUNC(RtlCompareString)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolWOW64(S_FUNC(NtOpenFile)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolWOW64(S_FUNC(NtReadFile)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolWOW64(S_FUNC(NtSetInformationFile)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolWOW64(S_FUNC(NtQueryInformationFile)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolWOW64(S_FUNC(NtClose)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	
	if (LoadSymbolWOW64(S_FUNC(NtAllocateVirtualMemory)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolWOW64(S_FUNC(NtFreeVirtualMemory)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolWOW64(S_FUNC(NtProtectVirtualMemory)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolWOW64(S_FUNC(NtCreateSection)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolWOW64(S_FUNC(NtMapViewOfSection)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolWOW64(S_FUNC(RtlInsertInvertedFunctionTable)))	return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolWOW64(S_FUNC(LdrpHandleTlsData)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolWOW64(S_FUNC(LdrLockLoaderLock)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolWOW64(S_FUNC(LdrUnlockLoaderLock)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolWOW64(S_FUNC(RtlAddVectoredExceptionHandler)))	return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolWOW64(S_FUNC(RtlRemoveVectoredExceptionHandler)))	return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolWOW64(S_FUNC(NtDelayExecution)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolWOW64(S_FUNC(LdrpHeap)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolWOW64(S_FUNC(LdrpVectorHandlerList)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolWOW64(S_FUNC(LdrpTlsList)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (IsWin11OrGreater() && GetOSBuildVersion() >= g_Win11_22H2)
	{
		if (LoadSymbolWOW64(LdrpInvertedFunctionTable_WOW64, "LdrpInvertedFunctionTables")) return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	}
	else
	{
		if (LoadSymbolWOW64(S_FUNC(LdrpInvertedFunctionTable))) return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	}

	if (GetOSVersion() == g_Win7)
	{
		if (LoadSymbolWOW64(S_FUNC(LdrpDefaultPath)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		if (LoadSymbolWOW64(S_FUNC(RtlpUnhandledExceptionFilter)))	return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	}

	if (IsWin8OrGreater())
	{
		if (LoadSymbolWOW64(S_FUNC(LdrGetDllPath)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

		if (LoadSymbolWOW64(S_FUNC(RtlRbRemoveNode)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		if (LoadSymbolWOW64(S_FUNC(LdrpModuleBaseAddressIndex)))	return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		if (LoadSymbolWOW64(S_FUNC(LdrpMappingInfoIndex)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	}

	if (IsWin81OrGreater())
	{
		if (LoadSymbolWOW64(S_FUNC(LdrProtectMrdata)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	}

	if (IsWin10OrGreater())
	{
		if (LoadSymbolWOW64(S_FUNC(LdrpPreprocessDllName)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		if (LoadSymbolWOW64(S_FUNC(LdrpLoadDllInternal)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		if (LoadSymbolWOW64(S_FUNC(LdrpDereferenceModule)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	}

	sym_ntdll_wow64.Cleanup();

	if (GetOSVersion() == g_Win7)
	{
		while (sym_kernel32_wow64_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
		{
			if (WaitForSingleObject(g_hInterruptImport, 10) == WAIT_OBJECT_0)
			{
				return INJ_ERR_IMPORT_INTERRUPT;
			}
		}

		sym_ret = sym_kernel32_wow64_ret.get();
		if (sym_ret != SYMBOL_ERR_SUCCESS)
		{
			INIT_ERROR_DATA(error_data, sym_ret);

			LOG(1, "WOW64 symbol loading failed: %08X\n", sym_ret);

			return INJ_ERR_SYMBOL_LOAD_FAIL;
		}

		sym_ret = sym_parser.Initialize(&sym_kernel32_wow64);
		if (sym_ret != SYMBOL_ERR_SUCCESS)
		{
			INIT_ERROR_DATA(error_data, sym_ret);

			LOG(1, "WOW64 symbol loading failed: %08X\n", sym_ret);

			return INJ_ERR_SYMBOL_PARSE_FAIL;
		}

		if (LoadSymbolWOW64(S_FUNC(UnhandledExceptionFilter),	IDX_KERNEL32))	return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		if (LoadSymbolWOW64(S_FUNC(SingleHandler),				IDX_KERNEL32))	return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		if (LoadSymbolWOW64(S_FUNC(DefaultHandler),				IDX_KERNEL32))	return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

		sym_kernel32_wow64.Cleanup();

		LOG(1, "WOW64 kernel32 symbols loaded\n");
	}

	sym_parser.Cleanup();

	LOG(1, "WOW64 ntdll symbols loaded\n");

	g_LibraryState = true;

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
			BYTE header[0x1000]{ 0 };
			if (!ReadProcessMemory(hTargetProc, ME32.modBaseAddr, header, sizeof(header), nullptr))
			{
				bRet = Module32NextW(hSnap, &ME32);

				continue;
			}

			IMAGE_DOS_HEADER	* pDos	= ReCa<IMAGE_DOS_HEADER		*>(header);
			IMAGE_NT_HEADERS32	* pNT	= ReCa<IMAGE_NT_HEADERS32	*>(header + pDos->e_lfanew);

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
	BYTE * modBase = ReCa<BYTE *>(hModule);

	if (!modBase)
	{
		return false;
	}

	BYTE * pBuffer = new(std::nothrow) BYTE[0x1000];
	if (!pBuffer)
	{
		return false;
	}

	if (!ReadProcessMemory(hTargetProc, modBase, pBuffer, 0x1000, nullptr))
	{
		delete[] pBuffer;

		return false;
	}

	auto * pNT = ReCa<IMAGE_NT_HEADERS32*>(ReCa<IMAGE_DOS_HEADER *>(pBuffer)->e_lfanew + pBuffer);
	auto * pDir = &pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	auto ExportSize = pDir->Size;
	auto DirRVA		= pDir->VirtualAddress;

	if (!ExportSize)
	{
		delete[] pBuffer;

		return false;
	}

	BYTE * pExpDirBuffer = new(std::nothrow) BYTE[ExportSize];
	auto * pExportDir = ReCa<IMAGE_EXPORT_DIRECTORY *>(pExpDirBuffer);

	if (!pExpDirBuffer)
	{
		delete[] pBuffer;

		return false;
	}

	if (!ReadProcessMemory(hTargetProc, modBase + DirRVA, pExpDirBuffer, ExportSize, nullptr))
	{
		delete[] pExpDirBuffer;
		delete[] pBuffer;

		return false;
	}

	BYTE * pBase = pExpDirBuffer - DirRVA;

	auto Forward = [&](DWORD FuncRVA, DWORD &pForwarded) -> bool
	{		
		std::string FullExport = ReCa<char *>(pBase + FuncRVA);

		auto PosSplitter = FullExport.find('.');
		if (PosSplitter == std::string::npos)
		{
			return false;
		}

		bool IsOrdinal	= false;
		WORD Ordinal	= 0;

		std::string FuncName = FullExport.substr(PosSplitter + 1);
		if (FuncName[0] == '#')
		{
			IsOrdinal	= true;
			Ordinal		= LOWORD(atoi(FuncName.substr(1).c_str()));
		}
		
		auto ModName	= FullExport.substr(0, PosSplitter);
		auto ModNameW	= CharArrayToStdWstring(ModName.c_str());

		if (IsOrdinal)
		{
			return GetProcAddressExW_WOW64(hTargetProc, ModNameW.c_str(), ReCa<char *>(Ordinal), pForwarded);
		}
		else
		{
			return GetProcAddressExW_WOW64(hTargetProc, ModNameW.c_str(), FuncName.c_str(), pForwarded);
		}
	};

	if (ReCa<ULONG_PTR>(szProcName) <= MAXWORD)
	{
		WORD Base		= LOWORD(pExportDir->Base - 1);
		WORD Ordinal	= LOWORD(szProcName) - Base;
		DWORD FuncRVA	= ReCa<DWORD *>(pBase + pExportDir->AddressOfFunctions)[Ordinal];

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

		DWORD CurrNameRVA	= ReCa<DWORD *>(pBase + pExportDir->AddressOfNames)[mid];
		char * szName		= ReCa<char *>(pBase + CurrNameRVA);

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
			WORD Ordinal = ReCa<WORD *>(pBase + pExportDir->AddressOfNameOrdinals)[mid];
			FuncRVA = ReCa<DWORD *>(pBase + pExportDir->AddressOfFunctions)[Ordinal];

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