#include "pch.h"

#include "main.h"

BOOL CALLBACK EnumWindowsCallback(HWND hWnd, LPARAM lParam)
{
	auto * data = reinterpret_cast<EnumWindowsCallback_Data*>(lParam);

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
	wchar_t InfoPath[MAX_PATH * 2]{ 0 };
	GetModuleFileNameW(GetModuleHandleW(nullptr), InfoPath, sizeof(InfoPath) / sizeof(InfoPath[0]));

	size_t size_out = 0;
	if (FAILED(StringCchLengthW(InfoPath, MAX_PATH * 2, &size_out)))
	{
		return SWHEX_ERR_INVALID_PATH;
	}

	wchar_t * pInfoEnd = InfoPath;
	pInfoEnd += size_out;
	while (*pInfoEnd-- != '\\');
	*(pInfoEnd + 2) = 0;

	StringCbCatW(InfoPath, sizeof(InfoPath), FILENAME);

	std::ifstream File(InfoPath, std::ios::ate);
	if (!File.good())
	{
		return SWHEX_ERR_CANT_OPEN_FILE;
	}

	auto FileSize = File.tellg();
	if (!FileSize)
	{
		File.close();
		return SWHEX_ERR_EMPTY_FILE;
	}

	File.seekg(0, std::ios::beg);

	char * info = new char[static_cast<size_t>(FileSize)];
	char * cpy = info;
	File.read(info, FileSize);

	File.close();

	DeleteFileW(InfoPath);

	char * pszPID = info;
	while (*info++ != '!');
	info[-1] = '\0';
	char * pszHook = info;

	DWORD ProcID = strtol(pszPID, nullptr, 10);
#ifdef _WIN64
	ULONG_PTR pHook = strtoll(pszHook, nullptr, 0x10);
#else
	DWORD pHook = strtol(pszHook, nullptr, 0x10);
#endif

	delete[] cpy;

	if (!ProcID || !pHook)
	{
		return SWHEX_ERR_INVALID_INFO;
	}

	EnumWindowsCallback_Data data;
	data.m_PID		= ProcID;
	data.m_pHook	= reinterpret_cast<HOOKPROC>(pHook);
	data.m_hModule	= LoadLibraryW(L"user32.dll");

	if (!EnumWindows(EnumWindowsCallback, reinterpret_cast<LPARAM>(&data)))
	{
		return SWHEX_ERR_ENUM_WINDOWS_FAIL;
	}

	if (data.m_HookData.empty())
	{
		return SWHEX_ERR_NO_WINDOWS;
	}

	for (auto i : data.m_HookData)
	{
		SetForegroundWindow(i.m_hWnd);
		SendMessageW(i.m_hWnd, WM_KEYDOWN, VK_SPACE, 0);
		Sleep(10);
		SendMessageW(i.m_hWnd, WM_KEYUP, VK_SPACE, 0);
		UnhookWindowsHookEx(i.m_hHook);
	}

	return SWHEX_ERR_SUCCESS;
}