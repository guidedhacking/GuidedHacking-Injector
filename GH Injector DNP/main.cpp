/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

#include "pch.h"

#include "main.h"

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, void * pReserved)
{
	UNREFERENCED_PARAMETER(pReserved);

	if (dwReason == DLL_PROCESS_ATTACH)
	{
#ifdef DEBUG_INFO
		AllocConsole();
		FILE * pFile = nullptr;
		freopen_s(&pFile, "CONOUT$", "w", stdout);
#endif

		CONSOLE_LOG("%s Loaded at %p\n", GH_DNP_NAME, hDll);

		g_hModuleBase = hDll;

		g_hMainThread = CreateThread(nullptr, 0, LoadDotNetBinary, nullptr, NULL, nullptr);
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		CONSOLE_LOG("DNP unloading\n");

		DWORD dwExitCode = STILL_ACTIVE;
		if (GetExitCodeThread(g_hMainThread, &dwExitCode))
		{
			if (dwExitCode == STILL_ACTIVE)
			{
				CONSOLE_LOG("DNP Terminating thread\n");
				TerminateThread(g_hMainThread, NULL);
			}
		}

		CloseHandle(g_hMainThread);
	}

	return TRUE;
}