#include "pch.h"

#include "Hook Scanner.h"

#define MOD_COUNT 3

static const wchar_t Modules[][MAX_PATH] =
{
	L"kernel32.dll",
	L"KernelBase.dll",
	L"ntdll.dll"
};

static const char k32_functions[][MAX_PATH] =
{
	"LoadLibraryExW",
	"BaseThreadInitThunk"
};

static const char kb_functions[][MAX_PATH] =
{
	"LoadLibraryExW",
};

static const char nt_functions[][MAX_PATH] =
{
	"LdrLoadDll",
	"LdrGetDllHandleEx",
	"LdrGetProcedureAddressForCaller",
	"LdrLockLoaderLock",
	"LdrUnlockLoaderLock",
	"memmove",
	"RtlAllocateHeap",
	"RtlFreeHeap",
	"RtlHashUnicodeString",
	"RtlRbInsertNodeEx",
	"NtOpenFile",
	"NtReadFile",
	"NtSetInformationFile",
	"NtQueryInformationFile",
	"NtCreateSection",
	"NtMapViewOfSection",
	"NtAllocateVirtualMemory",
	"NtProtectVirtualMemory"
};

bool __stdcall ValidateInjectionFunctions(DWORD dwTargetProcessId, DWORD & ErrorCode, DWORD & LastWin32Error, HookInfo * HookDataOut, UINT Count, UINT * CountOut)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	LOG(0, "ValidateInjectionFunctions:\n PID = %06X\n", dwTargetProcessId);

	if (!dwTargetProcessId)
	{
		ErrorCode = HOOK_SCAN_ERR_INVALID_PROCESS_ID;

		return false;
	}

	HANDLE hTargetProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwTargetProcessId);
	if (!hTargetProc)
	{
		LastWin32Error	= GetLastError();
		ErrorCode		= HOOK_SCAN_ERR_CANT_OPEN_PROCESS;

		LOG(0, "OpenProcess failed: %08X\n", LastWin32Error);

		return false;
	}

	bool bWow64 = !IsNativeProcess(hTargetProc);

#ifndef _WIN64
	if (!bWow64 && !IsNativeProcess(GetCurrentProcess()))
	{
		CloseHandle(hTargetProc);

		LOG(0, "WOW64 process can't scan x64 process\n");

		ErrorCode = HOOK_SCAN_ERR_PLATFORM_MISMATCH;

		return false;
	}

	bWow64 = false;
#endif

	std::vector<HookInfo> HookDataOutV;

	UINT ScanCount = 0;

	if (bWow64)
	{
#ifdef _WIN64

		LOG(0, "WOW64 hook scan\n");
		LOG(0, "Modules to scan:\n");

		HINSTANCE hModules[MOD_COUNT]{ 0 };
		for (int i = 0; i < MOD_COUNT; ++i)
		{
			hModules[i] = GetModuleHandleExW_WOW64(hTargetProc, Modules[i]);
			LOG(0, " %.11ls = %08X\n", Modules[i], MDWD(hModules[i]));
		}

		PROCESS_INFORMATION pi{ 0 };
		STARTUPINFOW si{ 0 };
		si.cb			= sizeof(si);
		si.dwFlags		= STARTF_USESHOWWINDOW;
		si.wShowWindow	= SW_HIDE;

		SECURITY_ATTRIBUTES sa{ 0 };
		sa.nLength			= sizeof(SECURITY_ATTRIBUTES);
		sa.bInheritHandle	= TRUE;

		HANDLE hEventStart = CreateEventEx(&sa, nullptr, CREATE_EVENT_MANUAL_RESET, EVENT_ALL_ACCESS);
		if (!hEventStart)
		{
			LastWin32Error	= GetLastError();
			ErrorCode		= HOOK_SCAN_ERR_CREATE_EVENT_FAILED;

			LOG(0, "CreateEventEx failed: %08X\n", LastWin32Error);

			CloseHandle(hTargetProc);

			return false;
		}

		HANDLE hEventEnd = CreateEventEx(&sa, nullptr, CREATE_EVENT_MANUAL_RESET, EVENT_ALL_ACCESS);
		if (!hEventEnd)
		{
			LastWin32Error	= GetLastError();
			ErrorCode		= HOOK_SCAN_ERR_CREATE_EVENT_FAILED;

			LOG(0, "CreateEventEx failed: %08X\n", LastWin32Error);

			CloseHandle(hEventStart);
			CloseHandle(hTargetProc);

			return false;
		}

		wchar_t hEventStart_string[9]{ 0 };
		_ultow_s(MDWD(hEventStart), hEventStart_string, 0x10);

		wchar_t hEventEnd_string[9]{ 0 };
		_ultow_s(MDWD(hEventEnd), hEventEnd_string, 0x10);

		auto RootPath = g_RootPathW + SM_EXE_FILENAME86;

		std::wstring CmdLine = L"\"" SM_EXE_FILENAME86 "\" " ID_WOW64 " ";
		CmdLine += hEventStart_string;
		CmdLine += L" ";
		CmdLine += hEventEnd_string;

		wchar_t szCmdLine[MAX_PATH]{ 0 };
		CmdLine.copy(szCmdLine, CmdLine.length()); //CmdLine will not exceed MAX_PATH characters (46 characters max)

		if (!CreateProcessW(RootPath.c_str(), szCmdLine, nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
		{
			LastWin32Error	= GetLastError();
			ErrorCode		= HOOK_SCAN_ERR_CREATE_PROCESS_FAILED;

			LOG(0, "CreateProcessW failed: %08X\n", LastWin32Error);

			CloseHandle(hEventStart);
			CloseHandle(hEventEnd);

			CloseHandle(hTargetProc);

			return false;
		}		

		DWORD dwWaitRet = WaitForSingleObject(hEventStart, 1000);
		if (dwWaitRet != WAIT_OBJECT_0)
		{
			if (dwWaitRet == WAIT_FAILED)
			{				
				LastWin32Error	= GetLastError();
				ErrorCode		= HOOK_SCAN_ERR_WAIT_FAILED;
			}
			else
			{
				LastWin32Error	= dwWaitRet;
				ErrorCode		= HOOK_SCAN_ERR_WAIT_TIMEOUT;
			}

			LOG(0, "WaitForSingleObject failed: %08X\n", LastWin32Error);

			CloseHandle(hEventStart);
			CloseHandle(hEventEnd);

			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);

			CloseHandle(hTargetProc);

			return false;
		}

		LOG(0, "Loading templates\n");

		if (hModules[0])
		{
			for (auto i = 0; i != sizeof(k32_functions) / sizeof(k32_functions[0]); ++i)
			{
				HookDataOutV.push_back({ Modules[0], k32_functions[i], hModules[0], nullptr, 0, 0, NULL });
				LOG(0, " %s\n", k32_functions[i]);
			}
		}

		if (hModules[1])
		{
			for (auto i = 0; i != sizeof(kb_functions) / sizeof(kb_functions[0]); ++i)
			{
				HookDataOutV.push_back({ Modules[1], kb_functions[i], hModules[1], nullptr, 0, 0, NULL });
				LOG(0, " %s\n", kb_functions[i]);
			}
		}

		if (hModules[2])
		{
			for (auto i = 0; i != sizeof(nt_functions) / sizeof(nt_functions[0]); ++i)
			{
				HookDataOutV.push_back({ Modules[2], nt_functions[i], hModules[2], nullptr, 0, 0, NULL });
				LOG(0, " %s\n", nt_functions[i]);
			}
		}

		LOG(0, "Scanning for hooks\n");

		for (auto & i : HookDataOutV)
		{
			if (ScanForHook_WOW64(i, hTargetProc, pi.hProcess))
			{
				LOG(0, " Hooked: %s (%d)\n", i.FunctionName, i.ChangeCount);

				if (ScanCount < Count)
				{
					HookDataOut[ScanCount] = i;
				}

				++ScanCount;
			}
		}

		SetEvent(hEventEnd);

		CloseHandle(hEventStart);
		CloseHandle(hEventEnd);
		
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
#endif
	}
	else
	{
		LOG(0, "Native hook scan\n");

		LOG(0, "Modules to scan:\n");

		HINSTANCE hModules[MOD_COUNT]{ 0 };
		for (int i = 0; i < MOD_COUNT; ++i)
		{
			hModules[i] = GetModuleHandleW(Modules[i]);
			LOG(0, " %.11ls = %p\n", Modules[i], hModules[i]);
		}

		LOG(0, "Loading templates\n");

		if (hModules[0])
		{
			for (auto i = 0; i != sizeof(k32_functions) / sizeof(k32_functions[0]); ++i)
			{
				HookDataOutV.push_back({ Modules[0], k32_functions[i], hModules[0], nullptr, 0, 0, NULL });
				LOG(0, " %s\n", k32_functions[i]);
			}
		}

		if (hModules[1])
		{
			for (auto i = 0; i != sizeof(kb_functions) / sizeof(kb_functions[0]); ++i)
			{
				HookDataOutV.push_back({ Modules[1], kb_functions[i], hModules[1], nullptr, 0, 0, NULL });
				LOG(0, " %s\n", kb_functions[i]);
			}
		}

		if (hModules[2])
		{
			for (auto i = 0; i != sizeof(nt_functions) / sizeof(nt_functions[0]); ++i)
			{
				HookDataOutV.push_back({ Modules[2], nt_functions[i], hModules[2], nullptr, 0, 0, NULL });
				LOG(0, " %s\n", nt_functions[i]);
			}
		}

		LOG(0, "Scanning for hooks\n");

		for (auto & i : HookDataOutV)
		{
			if(ScanForHook(i, hTargetProc))
			{
				LOG(0, " Hook: %s (%d)\n", i.FunctionName, i.ChangeCount);

				if (ScanCount < Count)
				{
					HookDataOut[ScanCount] = i;
				}

				++ScanCount;
			}
		}
	}

	CloseHandle(hTargetProc);

	if (CountOut)
	{
		*CountOut = ScanCount;
	}

	LOG(0, "%d hook(s) found\n", ScanCount);

	if (ScanCount > Count)
	{
		LOG(0, "Provided buffer too small: %d hooks found, buffer is %d hook entries big\n", ScanCount, Count);

		ErrorCode = HOOK_SCAN_ERR_BUFFER_TOO_SMALL;

		return false;
	}

	return true;
}

bool __stdcall RestoreInjectionFunctions(DWORD dwTargetProcessId, DWORD & ErrorCode, DWORD & LastWin32Error, HookInfo * HookDataIn, UINT Count, UINT * CountOut)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	LOG(0, "RestoreInjectionFunctions:\n PID = %06X\n", dwTargetProcessId);

	if (!dwTargetProcessId)
	{
		ErrorCode = HOOK_SCAN_ERR_INVALID_PROCESS_ID;

		return false;
	}

	HANDLE hTargetProc = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwTargetProcessId);
	if (!hTargetProc)
	{
		LastWin32Error	= GetLastError();
		ErrorCode		= HOOK_SCAN_ERR_CANT_OPEN_PROCESS;

		LOG(0, "OpenProcess failed: %08X\n", LastWin32Error);

		return false;
	}

	UINT SuccessCount = 0;
	for (UINT i = 0; i != Count; ++i)
	{
		if (HookDataIn[i].ChangeCount && (HookDataIn[i].ErrorCode == HOOK_SCAN_ERR_SUCCESS))
		{
			LOG(0, " Restoring %s\n", HookDataIn[i].FunctionName);

			if (!WriteProcessMemory(hTargetProc, HookDataIn[i].pFunc, HookDataIn[i].OriginalBytes, sizeof(HookDataIn[i].OriginalBytes), nullptr))
			{
				HookDataIn[i].ErrorCode = GetLastError();

				LOG(0, "  WriteProcessMemory failed: %08X\n", HookDataIn[i].ErrorCode);
			}
			else
			{
				++SuccessCount;
			}
		}
	}

	if (CountOut)
	{
		*CountOut = SuccessCount;
	}

	CloseHandle(hTargetProc);

	LOG(0, "%d of %d hook(s) restored\n", SuccessCount, Count);

	return true;
}

bool ScanForHook(HookInfo & Info, HANDLE hTargetProc)
{
	Info.pFunc = ReCa<void *>(GetProcAddress(Info.hModuleBase, Info.FunctionName));
	if (!Info.pFunc)
	{
		Info.ErrorCode = HOOK_SCAN_ERR_GETPROCADDRESS_FAILED;

		LOG(1, "GetProcAddress failed on %s with error %08X\n", Info.FunctionName, GetLastError());

		return false;
	}

	BYTE Buffer[HOOK_SCAN_BYTE_COUNT]{ 0 };
	if (!ReadProcessMemory(hTargetProc, Info.pFunc, Buffer, sizeof(Buffer), nullptr))
	{
		Info.ErrorCode = HOOK_SCAN_ERR_READ_PROCESS_MEMORY_FAILED;

		LOG(1, "ReadProcessMemory failed on %s with error %08X\n", Info.FunctionName, GetLastError());

		return false;
	}

	memcpy(Info.OriginalBytes, Info.pFunc, HOOK_SCAN_BYTE_COUNT);

	for (int i = 0; i != HOOK_SCAN_BYTE_COUNT; ++i)
	{
		if (Info.OriginalBytes[i] != Buffer[i])
		{
			++Info.ChangeCount;
		}
	}

	return (Info.ChangeCount != 0);
}