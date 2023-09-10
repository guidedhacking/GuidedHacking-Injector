/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

#include "pch.h"

#include "main.h"

BOOL CALLBACK _SWHEX_EnumWindowsCallback(HWND hWnd, LPARAM lParam)
{
	auto * data = reinterpret_cast<EnumWindowsCallback_Data *>(lParam);

	DWORD winPID = 0;
	DWORD winTID = GetWindowThreadProcessId(hWnd, &winPID);

	if (winPID == data->m_PID)
	{
		wchar_t szWindow[MAX_PATH]{ 0 };
		if (IsWindowVisible(hWnd) && GetWindowTextW(hWnd, szWindow, MAX_PATH))
		{
			if (GetClassNameW(hWnd, szWindow, MAX_PATH) && wcscmp(szWindow, L"ConsoleWindowClass"))
			{
				HHOOK hHook = SetWindowsHookEx(WH_CALLWNDPROC, data->m_pHook, data->m_hModule, winTID);
				if (hHook)
				{
					data->m_HookData.push_back({ hHook, hWnd });
				}
			}
		}
	}

	return TRUE;
}

DWORD _SetWindowsHookEx()
{
	auto ModuleBase = GetModuleHandleW(nullptr);
	if (!ModuleBase)
	{
		return SWHEX_ERR_NO_MODULEBASE;
	}

	wchar_t szInfoPath[MAX_PATH * 2]{ 0 };
	size_t max_size = sizeof(szInfoPath) / sizeof(wchar_t);

	DWORD dwRet = GetModuleFileNameW(ModuleBase, szInfoPath, (DWORD)max_size);
	if (!dwRet || GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		return SWHEX_ERR_NO_PATH;
	}

	std::wstring InfoPath = szInfoPath;
	auto pos = InfoPath.find_last_of('\\');
	if (pos == std::wstring::npos)
	{
		return SWHEX_ERR_INVALID_PATH;
	}

	InfoPath.erase(pos, InfoPath.back());
	InfoPath += FILENAME;

	std::ifstream File(InfoPath);
	if (!File.good())
	{
		File.close();

		DeleteFileW(InfoPath.c_str());

		return SWHEX_ERR_CANT_OPEN_FILE;
	}

	std::stringstream info;
	info << File.rdbuf();
	
	File.close();

	DeleteFileW(InfoPath.c_str());

	std::string sPID = info.str();
	if (sPID.length() < 1)
	{
		return SWHEX_ERR_EMPTY_FILE;
	}

	pos = sPID.find('!');
	if (pos == std::string::npos)
	{
		return SWHEX_ERR_INVALID_INFO;
	}
	
	std::string sHook = sPID.substr(pos + 1, std::string::npos);
	sPID.erase(pos, std::string::npos);

	DWORD ProcID = strtol(sPID.c_str(), nullptr, 10);

#ifdef _WIN64
	ULONG_PTR pHook = strtoll(sHook.c_str(), nullptr, 0x10);
#else
	DWORD pHook = strtol(sHook.c_str(), nullptr, 0x10);
#endif

	if (!ProcID || !pHook)
	{
		return SWHEX_ERR_INVALID_INFO;
	}

	EnumWindowsCallback_Data data;
	data.m_PID		= ProcID;
	data.m_pHook	= reinterpret_cast<HOOKPROC>(pHook);
	data.m_hModule	= LoadLibraryW(L"user32.dll");

	if (!EnumWindows(_SWHEX_EnumWindowsCallback, reinterpret_cast<LPARAM>(&data)))
	{
		return SWHEX_ERR_ENUM_WINDOWS_FAIL;
	}

	if (data.m_HookData.empty())
	{
		return SWHEX_ERR_NO_WINDOWS;
	}

	for (const auto & i : data.m_HookData)
	{
		SetForegroundWindow(i.m_hWnd);
		SendMessageW(i.m_hWnd, WM_KEYDOWN, VK_SPACE, 0);
		Sleep(10);
		SendMessageW(i.m_hWnd, WM_KEYUP, VK_SPACE, 0);
		UnhookWindowsHookEx(i.m_hHook);
	}

	return SWHEX_ERR_SUCCESS;
}