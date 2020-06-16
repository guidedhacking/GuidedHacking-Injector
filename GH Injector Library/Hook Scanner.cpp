#include "pch.h"

#include "Hook Scanner.h"

static const char Modules[][MAX_PATH] =
{
	"kernel32.dll",
	"KernelBase.dll",
	"ntdll.dll"
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
	"RtlMoveMemory",
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

		return false;
	}

	bool bWow64 = !IsNativeProcess(hTargetProc);

#ifndef _WIN64
	if (!bWow64 && !IsNativeProcess(GetCurrentProcess()))
	{
		CloseHandle(hTargetProc);

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

		HINSTANCE h_remote_K32	= GetModuleHandleExA_WOW64(hTargetProc, Modules[0]);
		HINSTANCE h_remote_KB	= GetModuleHandleExA_WOW64(hTargetProc, Modules[1]);
		HINSTANCE h_remote_NT	= GetModuleHandleExA_WOW64(hTargetProc, Modules[2]);

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

			CloseHandle(hTargetProc);

			return false;
		}

		HANDLE hEventEnd = CreateEventEx(&sa, nullptr, CREATE_EVENT_MANUAL_RESET, EVENT_ALL_ACCESS);
		if (!hEventEnd)
		{
			CloseHandle(hEventStart);

			LastWin32Error = GetLastError();
			ErrorCode = HOOK_SCAN_ERR_CREATE_EVENT_FAILED;

			CloseHandle(hTargetProc);

			return false;
		}

		wchar_t hEventStart_string[9]{ 0 };
		_ultow_s(MDWD(hEventStart), hEventStart_string, 0x10);

		wchar_t hEventEnd_string[9]{ 0 };
		_ultow_s(MDWD(hEventEnd), hEventEnd_string, 0x10);

		wchar_t RootPath[MAX_PATH * 2]{ 0 };
		StringCbCopyW(RootPath, sizeof(RootPath), g_RootPathW.c_str());
		StringCbCatW(RootPath, sizeof(RootPath), SM_EXE_FILENAME86);

		wchar_t cmdLine[MAX_PATH]{ 0 };
		StringCbCatW(cmdLine, sizeof(cmdLine), L"\"");
		StringCbCatW(cmdLine, sizeof(cmdLine), SM_EXE_FILENAME86);
		StringCbCatW(cmdLine, sizeof(cmdLine), L"\" 1 ");
		StringCbCatW(cmdLine, sizeof(cmdLine), hEventStart_string);
		StringCbCatW(cmdLine, sizeof(cmdLine), L" ");
		StringCbCatW(cmdLine, sizeof(cmdLine), hEventEnd_string);

		if (!CreateProcessW(RootPath, cmdLine, nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
		{
			LastWin32Error	= GetLastError();
			ErrorCode		= HOOK_SCAN_ERR_CREATE_PROCESS_FAILED;

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

			CloseHandle(hEventStart);
			CloseHandle(hEventEnd);

			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);

			CloseHandle(hTargetProc);

			return false;
		}

		if (h_remote_K32)
		{
			for (auto i = 0; i != sizeof(k32_functions) / sizeof(k32_functions[0]); ++i)
			{
				HookDataOutV.push_back({ Modules[0], k32_functions[i], h_remote_K32, nullptr, 0, 0, NULL });
			}
		}

		if (h_remote_KB)
		{
			for (auto i = 0; i != sizeof(kb_functions) / sizeof(kb_functions[0]); ++i)
			{
				HookDataOutV.push_back({ Modules[1], kb_functions[i], h_remote_KB, nullptr, 0, 0, NULL });
			}
		}

		if (h_remote_NT)
		{
			for (auto i = 0; i != sizeof(nt_functions) / sizeof(nt_functions[0]); ++i)
			{
				HookDataOutV.push_back({ Modules[2], nt_functions[i], h_remote_NT, nullptr, 0, 0, NULL });
			}
		}

		for (auto & i : HookDataOutV)
		{
			if (ScanForHook_WOW64(i, hTargetProc, pi.hProcess))
			{
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
		HINSTANCE h_remote_K32	= GetModuleHandleA(Modules[0]);
		HINSTANCE h_remote_KB	= GetModuleHandleA(Modules[1]);
		HINSTANCE h_remote_NT	= GetModuleHandleA(Modules[2]);

		if (h_remote_K32)
		{
			for (auto i = 0; i != sizeof(k32_functions) / sizeof(k32_functions[0]); ++i)
			{
				HookDataOutV.push_back({ Modules[0], k32_functions[i], h_remote_K32, nullptr, 0, 0, NULL });
			}
		}

		if (h_remote_KB)
		{
			for (auto i = 0; i != sizeof(kb_functions) / sizeof(kb_functions[0]); ++i)
			{
				HookDataOutV.push_back({ Modules[1], kb_functions[i], h_remote_KB, nullptr, 0, 0, NULL });
			}
		}

		if (h_remote_NT)
		{
			for (auto i = 0; i != sizeof(nt_functions) / sizeof(nt_functions[0]); ++i)
			{
				HookDataOutV.push_back({ Modules[2], nt_functions[i], h_remote_NT, nullptr, 0, 0, NULL });
			}
		}

		for (auto & i : HookDataOutV)
		{
			if(ScanForHook(i, hTargetProc))
			{
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

	if (ScanCount > Count)
	{
		return false;
	}

	return true;
}

bool __stdcall RestoreInjectionFunctions(DWORD dwTargetProcessId, DWORD & ErrorCode, DWORD & LastWin32Error, HookInfo * HookDataIn, UINT Count, UINT * CountOut)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

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

		return false;
	}

	UINT SuccessCount = 0;
	for (UINT i = 0; i != Count; ++i)
	{
		if (HookDataIn[i].ChangeCount && (HookDataIn[i].ErrorCode == HOOK_SCAN_ERR_SUCCESS))
		{
			if (!WriteProcessMemory(hTargetProc, HookDataIn[i].pFunc, HookDataIn[i].OriginalBytes, sizeof(HookDataIn[i].OriginalBytes), nullptr))
			{
				HookDataIn[i].ErrorCode = GetLastError();
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

	return true;
}

bool ScanForHook(HookInfo & Info, HANDLE hTargetProc)
{
	Info.pFunc = ReCa<void*>(GetProcAddress(Info.hModuleBase, Info.FunctionName));
	if (!Info.pFunc)
	{
		Info.ErrorCode = HOOK_SCAN_ERR_GETPROCADDRESS_FAILED;

		return false;
	}

	BYTE Buffer[HOOK_SCAN_BYTE_COUNT]{ 0 };
	if (!ReadProcessMemory(hTargetProc, Info.pFunc, Buffer, sizeof(Buffer), nullptr))
	{
		Info.ErrorCode = HOOK_SCAN_ERR_READ_PROCESS_MEMORY_FAILED;

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