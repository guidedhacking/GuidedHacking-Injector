/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

#include "pch.h"

#include "main.h"

#pragma comment(linker, "/SUBSYSTEM:WINDOWS /ENTRY:wmainCRTStartup")

int wmain(int argc, wchar_t * argv[])
{
	if (argc < 2)
	{
		return SM_ERR_INVALID_ARGC;
	}

	if (argv[1][0] == ID_SWHEX)
	{
		return (int)_SetWindowsHookEx();
	}
	else if (argv[1][0] == ID_KC)
	{
		return (int)_KernelCallbackTable();
	}
#ifndef _WIN64
	else if (argv[1][0] == ID_WOW64)
	{
		HANDLE hEventStart	= reinterpret_cast<HANDLE>(wcstol(argv[2], nullptr, 0x10));
		HANDLE hEventEnd	= reinterpret_cast<HANDLE>(wcstol(argv[3], nullptr, 0x10));

		SignalObjectAndWait(hEventStart, hEventEnd, INFINITE, FALSE);

		CloseHandle(hEventStart);
		CloseHandle(hEventEnd);

		return SM_ERR_SUCCESS;
	}
#endif
	
	return SM_ERR_INVALID_ARGV;
}