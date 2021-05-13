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
	wchar_t InfoPath[MAX_PATH * 2]{ 0 };
	GetModuleFileNameW(GetModuleHandleW(nullptr), InfoPath, sizeof(InfoPath) / sizeof(InfoPath[0]));

	size_t size_out = 0;
	if (FAILED(StringCchLengthW(InfoPath, MAX_PATH * 2, &size_out)))
	{
		return KC_ERR_INVALID_PATH;
	}

	wchar_t * pInfoEnd = InfoPath;
	pInfoEnd += size_out;
	while (*pInfoEnd-- != '\\');
	*(pInfoEnd + 2) = 0;

	StringCbCatW(InfoPath, sizeof(InfoPath), FILENAME);

	std::ifstream File(InfoPath, std::ios::ate);
	if (!File.good())
	{
		return KC_ERR_CANT_OPEN_FILE;
	}

	auto FileSize = File.tellg();
	if (!FileSize)
	{
		File.close();
		return KC_ERR_EMPTY_FILE;
	}

	File.seekg(0, std::ios::beg);

	char * info = new char[static_cast<size_t>(FileSize)];
	File.read(info, FileSize);

	File.close();

	DeleteFileW(InfoPath);

	DWORD ProcID = strtol(info, nullptr, 10);

	delete[] info;

	if (!ProcID)
	{
		return SWHEX_ERR_INVALID_INFO;
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

	for (auto i : data.m_HookData)
	{
		SendMessage(i.m_hWnd, WM_COPYDATA, reinterpret_cast<WPARAM>(i.m_hWnd), reinterpret_cast<LPARAM>(&cds));
	}

	return KC_ERR_SUCCESS;
}