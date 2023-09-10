/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

#include "pch.h"

#include "main.h"

BOOL CALLBACK _KC_EnumWindowsCallback(HWND hWnd, LPARAM lParam)
{
	auto * data = reinterpret_cast<EnumWindowsCallback_Data *>(lParam);

	DWORD winPID = 0;
	GetWindowThreadProcessId(hWnd, &winPID);

	if (winPID == data->m_PID)
	{
		wchar_t szWindow[MAX_PATH]{ 0 };
		if (IsWindowVisible(hWnd) && GetWindowTextW(hWnd, szWindow, MAX_PATH))
		{
			data->m_HookData.push_back({ NULL, hWnd });
		}
	}

	return TRUE;
}

DWORD _KernelCallbackTable()
{
	auto ModuleBase = GetModuleHandleW(nullptr);
	if (!ModuleBase)
	{
		return KC_ERR_NO_MODULEBASE;
	}

	wchar_t szInfoPath[MAX_PATH * 2]{ 0 };
	size_t max_size = sizeof(szInfoPath) / sizeof(wchar_t);

	DWORD dwRet = GetModuleFileNameW(ModuleBase, szInfoPath, (DWORD)max_size);
	if (!dwRet || GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		return KC_ERR_NO_PATH;
	}

	std::wstring InfoPath = szInfoPath;
	auto pos = InfoPath.find_last_of('\\');
	if (pos == std::wstring::npos)
	{
		return KC_ERR_INVALID_PATH;
	}

	InfoPath.erase(pos, InfoPath.back());
	InfoPath += FILENAME;

	std::ifstream File(InfoPath);
	if (!File.good())
	{
		File.close();

		DeleteFileW(InfoPath.c_str());

		return KC_ERR_CANT_OPEN_FILE;
	}

	std::stringstream info;
	info << File.rdbuf();

	File.close();

	DeleteFileW(InfoPath.c_str());

	std::string sPID = info.str();
	if (sPID.length() < 1)
	{
		return KC_ERR_EMPTY_FILE;
	}

	DWORD ProcID = strtol(sPID.c_str(), nullptr, 10);

	if (!ProcID)
	{
		return KC_ERR_INVALID_INFO;
	}

	EnumWindowsCallback_Data data;
	data.m_PID		= ProcID;
	data.m_pHook	= NULL;
	data.m_hModule	= LoadLibraryW(L"user32.dll");

	if (!EnumWindows(_KC_EnumWindowsCallback, reinterpret_cast<LPARAM>(&data)))
	{
		return KC_ERR_ENUM_WINDOWS_FAIL;
	}

	if (data.m_HookData.empty())
	{
		return KC_ERR_NO_WINDOWS;
	}

	TCHAR msg[] = TEXT("This sentence is false.");

	COPYDATASTRUCT cds{ 0 };
	cds.dwData = 1;
	cds.lpData = msg;
	cds.cbData = sizeof(msg);	

	for (const auto & i : data.m_HookData)
	{
		SendMessage(i.m_hWnd, WM_COPYDATA, reinterpret_cast<WPARAM>(i.m_hWnd), reinterpret_cast<LPARAM>(&cds));
	}

	return KC_ERR_SUCCESS;
}