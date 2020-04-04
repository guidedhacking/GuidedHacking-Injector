#include "pch.h"

#include "Hook Scanner.h"

bool __stdcall ValidateInjectionFunctions(DWORD dwTargetProcessId, DWORD & ErrorCode, DWORD & LastWin32Error, std::vector<HookInfo> & HookDataOut)
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
	
	if (bWow64)
	{
#ifdef _WIN64
		std::string kernel32_path	("C:\\Windows\\SysWOW64\\kernel32.dll");
		std::string kernelbase_path	("C:\\Windows\\SysWOW64\\KernelBase.dll");
		std::string ntdll_path		("C:\\Windows\\SysWOW64\\ntdll.dll");

		std::string kernel32_name	("kernel32.dll");
		std::string kernelbase_name	("KernelBase.dll");
		std::string ntdll_name		("ntdll.dll");

		HINSTANCE h_remote_K32	= GetModuleHandleExA_WOW64(hTargetProc, kernel32_name.c_str());
		HINSTANCE h_remote_KB	= GetModuleHandleExA_WOW64(hTargetProc, kernelbase_name.c_str());
		HINSTANCE h_remote_NT	= GetModuleHandleExA_WOW64(hTargetProc, ntdll_name.c_str());

		PROCESS_INFORMATION pi{ 0 };
		STARTUPINFOW si{ 0 };
		si.cb			= sizeof(si);
		si.dwFlags		= STARTF_USESHOWWINDOW;
		si.wShowWindow	= SW_HIDE;
		
		wchar_t RootPath[MAX_PATH * 2]{ 0 };
		if (!GetOwnModulePath(RootPath, sizeof(RootPath) / sizeof(RootPath[0])))
		{
			ErrorCode = HOOK_SCAN_ERR_CANT_GET_OWN_MODULE_PATH;

			CloseHandle(hTargetProc);

			return false;
		}

		SECURITY_ATTRIBUTES sa{ 0 };
		sa.nLength			= sizeof(SECURITY_ATTRIBUTES);
		sa.bInheritHandle	= TRUE;

		HANDLE hEvent = CreateEventEx(&sa, nullptr, NULL, EVENT_ALL_ACCESS);
		if (!hEvent)
		{
			LastWin32Error	= GetLastError();
			ErrorCode		= HOOK_SCAN_ERR_CREATE_EVENT_FAILED;

			CloseHandle(hTargetProc);

			return false;
		}

		wchar_t hEvent_string[9]{ 0 };
		_ultow_s(MDWD(hEvent), hEvent_string, 0x10);

		StringCbCatW(RootPath, sizeof(RootPath), SM_EXE_FILENAME86);

		wchar_t cmdLine[MAX_PATH]{ 0 };
		StringCbCatW(cmdLine, sizeof(cmdLine), L"\"");
		StringCbCatW(cmdLine, sizeof(cmdLine), SM_EXE_FILENAME86);
		StringCbCatW(cmdLine, sizeof(cmdLine), L"\" 1 ");
		StringCbCatW(cmdLine, sizeof(cmdLine), hEvent_string);

		if (!CreateProcessW(RootPath, cmdLine, nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
		{
			LastWin32Error	= GetLastError();
			ErrorCode		= HOOK_SCAN_ERR_CREATE_PROCESS_FAILED;

			CloseHandle(hEvent);

			CloseHandle(hTargetProc);

			return false;
		}

		DWORD dwWaitRet = WaitForSingleObject(hEvent, 500);
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

			CloseHandle(hEvent);

			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);

			CloseHandle(hTargetProc);

			return false;
		}

		if (h_remote_K32)
		{
			HookDataOut.push_back({ kernel32_name, "LoadLibraryA",			h_remote_K32, ReCa<BYTE*>(pi.hProcess), nullptr, 0, 0, NULL });
			HookDataOut.push_back({ kernel32_name, "LoadLibraryExA",		h_remote_K32, ReCa<BYTE*>(pi.hProcess), nullptr, 0, 0, NULL });
			HookDataOut.push_back({ kernel32_name, "LoadLibraryExW",		h_remote_K32, ReCa<BYTE*>(pi.hProcess), nullptr, 0, 0, NULL });
			HookDataOut.push_back({ kernel32_name, "GetModuleHandleA",		h_remote_K32, ReCa<BYTE*>(pi.hProcess), nullptr, 0, 0, NULL });
			HookDataOut.push_back({ kernel32_name, "GetProcAddress",		h_remote_K32, ReCa<BYTE*>(pi.hProcess), nullptr, 0, 0, NULL });
			HookDataOut.push_back({ kernel32_name, "BaseThreadInitThunk",	h_remote_K32, ReCa<BYTE*>(pi.hProcess), nullptr, 0, 0, NULL });
		}

		if (h_remote_KB)
		{
			HookDataOut.push_back({ kernelbase_name, "LoadLibraryA",			h_remote_KB, ReCa<BYTE*>(pi.hProcess), nullptr, 0, 0, NULL });
			HookDataOut.push_back({ kernelbase_name, "LoadLibraryExA",			h_remote_KB, ReCa<BYTE*>(pi.hProcess), nullptr, 0, 0, NULL });
			HookDataOut.push_back({ kernelbase_name, "LoadLibraryExW",			h_remote_KB, ReCa<BYTE*>(pi.hProcess), nullptr, 0, 0, NULL });
			HookDataOut.push_back({ kernelbase_name, "GetModuleHandleA",		h_remote_KB, ReCa<BYTE*>(pi.hProcess), nullptr, 0, 0, NULL });
			HookDataOut.push_back({ kernelbase_name, "GetProcAddressForCaller", h_remote_KB, ReCa<BYTE*>(pi.hProcess), nullptr, 0, 0, NULL });
		}

		if (h_remote_NT)
		{
			HookDataOut.push_back({ ntdll_name, "LdrLoadDll",						h_remote_NT, ReCa<BYTE*>(pi.hProcess), nullptr, 0, 0, NULL });
			HookDataOut.push_back({ ntdll_name, "LdrGetDllHandle",					h_remote_NT, ReCa<BYTE*>(pi.hProcess), nullptr, 0, 0, NULL });
			HookDataOut.push_back({ ntdll_name, "LdrGetProcedureAddressForCaller",	h_remote_NT, ReCa<BYTE*>(pi.hProcess), nullptr, 0, 0, NULL });
		}

		for (int i = 0; i != HookDataOut.size(); ++i)
		{
			ScanForHook_WOW64(HookDataOut.at(i), hTargetProc);
		}

		SetEvent(hEvent);
		CloseHandle(hEvent);
		
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
#endif
	}
	else
	{
		std::string kernel32_name	("kernel32.dll");
		std::string kernelbase_name	("KernelBase.dll");
		std::string ntdll_name		("ntdll.dll");

		HINSTANCE h_remote_K32	= GetModuleHandleExA(hTargetProc, kernel32_name.c_str());
		HINSTANCE h_remote_KB	= GetModuleHandleExA(hTargetProc, kernelbase_name.c_str());
		HINSTANCE h_remote_NT	= GetModuleHandleExA(hTargetProc, ntdll_name.c_str());

		BYTE * p_mapped_K32 = ReCa<BYTE*>(LoadLibrary(TEXT("kernel32.dll")));
		BYTE * p_mapped_KB	= ReCa<BYTE*>(LoadLibrary(TEXT("KernelBase.dll")));
		BYTE * p_mapped_NT	= ReCa<BYTE*>(LoadLibrary(TEXT("ntdll.dll")));

		if (h_remote_K32 && p_mapped_K32)
		{
			HookDataOut.push_back({ kernel32_name, "LoadLibraryA",			h_remote_K32, p_mapped_K32, nullptr, 0, 0, NULL });
			HookDataOut.push_back({ kernel32_name, "LoadLibraryExA",		h_remote_K32, p_mapped_K32, nullptr, 0, 0, NULL });
			HookDataOut.push_back({ kernel32_name, "LoadLibraryExW",		h_remote_K32, p_mapped_K32, nullptr, 0, 0, NULL });
			HookDataOut.push_back({ kernel32_name, "GetModuleHandleA",		h_remote_K32, p_mapped_K32, nullptr, 0, 0, NULL });
			HookDataOut.push_back({ kernel32_name, "GetProcAddress",		h_remote_K32, p_mapped_K32, nullptr, 0, 0, NULL });
			HookDataOut.push_back({ kernel32_name, "BaseThreadInitThunk",	h_remote_K32, p_mapped_K32, nullptr, 0, 0, NULL });
		}

		if (h_remote_KB && p_mapped_KB)
		{
			HookDataOut.push_back({ kernelbase_name, "LoadLibraryA",			h_remote_KB, p_mapped_KB, nullptr, 0, 0, NULL });
			HookDataOut.push_back({ kernelbase_name, "LoadLibraryExA",			h_remote_KB, p_mapped_KB, nullptr, 0, 0, NULL });
			HookDataOut.push_back({ kernelbase_name, "LoadLibraryExW",			h_remote_KB, p_mapped_KB, nullptr, 0, 0, NULL });
			HookDataOut.push_back({ kernelbase_name, "GetModuleHandleA",		h_remote_KB, p_mapped_KB, nullptr, 0, 0, NULL });
			HookDataOut.push_back({ kernelbase_name, "GetProcAddressForCaller", h_remote_KB, p_mapped_KB, nullptr, 0, 0, NULL });
		}
		
		if (h_remote_NT && p_mapped_NT)
		{
			HookDataOut.push_back({ ntdll_name, "LdrLoadDll",						h_remote_NT, p_mapped_NT, nullptr, 0, 0, NULL });
			HookDataOut.push_back({ ntdll_name, "LdrGetDllHandle",					h_remote_NT, p_mapped_NT, nullptr, 0, 0, NULL });
			HookDataOut.push_back({ ntdll_name, "LdrGetProcedureAddressForCaller",	h_remote_NT, p_mapped_NT, nullptr, 0, 0, NULL });
		}

		for (UINT i = 0; i != HookDataOut.size(); ++i)
		{
			ScanForHook(HookDataOut.at(i), hTargetProc);
		}
	}

	CloseHandle(hTargetProc);

	return true;
}

bool __stdcall RestoreInjectionFunctions(DWORD dwTargetProcessId, DWORD & ErrorCode, DWORD & LastWin32Error, std::vector<HookInfo> & HookDataIn)
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

	for (auto i : HookDataIn)
	{
		if (i.ChangeCount && (i.ErrorCode == HOOK_SCAN_ERR_SUCCESS))
		{
			if (!WriteProcessMemory(hTargetProc, i.pFunc, i.OriginalBytes, sizeof(i.OriginalBytes), nullptr))
			{
				i.ErrorCode = GetLastError();
			}
		}
	}

	CloseHandle(hTargetProc);

	return true;
}

bool ScanForHook(HookInfo & Info, HANDLE hTargetProc)
{
	Info.pFunc = ReCa<void*>(GetProcAddress(ReCa<HINSTANCE>(Info.pReference), Info.FunctionName.c_str()));
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