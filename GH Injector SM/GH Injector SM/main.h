#pragma once

#include "pch.h"

#ifdef _WIN64
#define FILENAME L"\\SM64.txt"
#else
#define FILENAME L"\\SM86.txt"
#endif


#define SM_ERR_SUCCESS		0x00000000
#define SM_ERR_INVALID_ARGC	0x30000001
#define SM_ERR_INVALID_ARGV	0x30000002

#define SWHEX_ERR_SUCCESS			0x00000000
#define SWHEX_ERR_INVALID_PATH		0x30100001
#define SWHEX_ERR_CANT_OPEN_FILE	0x30100002
#define SWHEX_ERR_EMPTY_FILE		0x30100003
#define SWHEX_ERR_INVALID_INFO		0x30100004
#define SWHEX_ERR_ENUM_WINDOWS_FAIL 0x30100005
#define SWHEX_ERR_NO_WINDOWS		0x30100006

struct HookData
{
	HHOOK	m_hHook;
	HWND	m_hWnd;
};

struct EnumWindowsCallback_Data
{
	std::vector<HookData>	m_HookData;
	DWORD					m_PID		= 0;
	HOOKPROC				m_pHook		= nullptr;
	HINSTANCE				m_hModule	= NULL;
};

DWORD _SetWindowsHookEx();