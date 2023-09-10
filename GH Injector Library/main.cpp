/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

#include "pch.h"

#include "Import Handler.h"

#if !defined(_WIN64) && defined (DUMP_SHELLCODE)
#include "Manual Mapping.h"
#include "Injection Internal.h"
#endif

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, void * pReserved)
{
	UNREFERENCED_PARAMETER(pReserved);
	
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		GetOSVersion();

#if !defined(_WIN64) && defined (DUMP_SHELLCODE)
		HINSTANCE	dummy_instance{ 0 };
		ERROR_DATA	dummy_data{ 0 };
		INJECTION_SOURCE s;
		InjectDLL(s, nullptr, INJECTION_MODE::IM_LoadLibraryExW, LAUNCH_METHOD::LM_NtCreateThreadEx, NULL, dummy_instance, 0, dummy_data);
		MMAP_NATIVE::ManualMap(s, nullptr, LAUNCH_METHOD::LM_NtCreateThreadEx, NULL, dummy_instance, 0, dummy_data);
#endif

		LOG(0, "GH Injector V%ls loaded\nImagebase = %p\n", GH_INJ_VERSIONW, hDll);

		g_hInjMod = hDll;

		if (!GetOwnModulePathW(g_RootPathW))
		{
			LOG(0, "Couldn't resolve own module path (unicode)\n");

			return FALSE;
		}

		wchar_t * szWindowsDir = nullptr;
		if (_wdupenv_s(&szWindowsDir, nullptr, L"WINDIR") || !szWindowsDir)
		{
			LOG(0, "Couldn't resolve %%WINDIR%%\n");

			if (szWindowsDir)
			{
				free(szWindowsDir);
			}

			return FALSE;
		}

		std::wstring szNtDllNative = szWindowsDir;
		szNtDllNative += L"\\System32\\ntdll.dll";

		LOG(0, "Launching PDB thread(s)\n");

		sym_ntdll_native_ret = std::async(std::launch::async, &SYMBOL_LOADER::Initialize, &sym_ntdll_native, szNtDllNative, g_RootPathW, nullptr, false, true, false);

#ifdef _WIN64
		std::wstring szNtDllWOW64 = szWindowsDir;
		szNtDllWOW64 += L"\\SysWOW64\\ntdll.dll";

		sym_ntdll_wow64_ret = std::async(std::launch::async, &SYMBOL_LOADER::Initialize, &sym_ntdll_wow64, szNtDllWOW64, g_RootPathW, nullptr, false, true, false);
#endif

		if (GetOSVersion() == g_Win7)
		{
			std::wstring szKernel32Native = szWindowsDir;
			szKernel32Native += L"\\System32\\kernel32.dll";

			LOG(0, "Launching PDB thread(s)\n");

			sym_kernel32_native_ret = std::async(std::launch::async, &SYMBOL_LOADER::Initialize, &sym_kernel32_native, szKernel32Native, g_RootPathW, nullptr, false, true, false);

#ifdef _WIN64
			std::wstring szKernel32WOW64 = szWindowsDir;
			szKernel32WOW64 += L"\\SysWOW64\\kernel32.dll";

			sym_kernel32_wow64_ret = std::async(std::launch::async, &SYMBOL_LOADER::Initialize, &sym_kernel32_wow64, szKernel32WOW64, g_RootPathW, nullptr, false, true, false);
#endif
		}

		free(szWindowsDir);

		LOG(0, "Launching import resolver thread\n");

		import_handler_ret = std::async(std::launch::async, &ResolveImports, std::ref(import_handler_error_data));

#ifdef _WIN64
		import_handler_wow64_ret = std::async(std::launch::async, &ResolveImports_WOW64, std::ref(import_handler_error_data));
#endif

		g_hRunningEvent	= CreateEvent(nullptr, TRUE, FALSE, nullptr);
		if (!g_hRunningEvent)
		{
			LOG(0, "Failed to create event (1): %08X\n", GetLastError());
		}

		g_hInterruptEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
		if (!g_hInterruptEvent)
		{
			LOG(0, "Failed to create event (2): %08X\n", GetLastError());
		}

		g_hInterruptedEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
		if (!g_hInterruptedEvent)
		{
			LOG(0, "Failed to create event (3): %08X\n", GetLastError());
		}

		g_hInterruptImport = CreateEvent(nullptr, TRUE, FALSE, nullptr);
		if (!g_hInterruptImport)
		{
			LOG(0, "Failed to create event (4): %08X\n", GetLastError());
		}

		LOG(0, "DllMain exit\n");
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		if (sym_ntdll_native_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
		{
			LOG(0, "ntdll.pdb download thread didn't exit properly.\n");
		}

#ifdef _WIN64
		if (sym_ntdll_wow64_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
		{
			LOG(0, "wntdll.pdb download thread didn't exit properly.\n");
		}
#endif

		if (GetOSVersion() == g_Win7)
		{
			if (sym_kernel32_native_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
			{
				LOG(0, "kernel32.pdb download thread didn't exit properly.\n");
			}

#ifdef _WIN64
			if (sym_kernel32_wow64_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
			{
				LOG(0, "wkernel32.pdb download thread didn't exit properly.\n");
			}
#endif
		}

		if (import_handler_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
		{
			LOG(0, "import handler (native) thread didn't exit properly.\n");
		}

#ifdef _WIN64
		if (import_handler_wow64_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
		{
			LOG(0, "import handler (wow64) thread didn't exit properly.\n");
		}
#endif

		if (g_hRunningEvent)
		{
			CloseHandle(g_hRunningEvent);
		}

		if (g_hInterruptEvent)
		{
			CloseHandle(g_hInterruptEvent);
		}

		if (g_hInterruptedEvent)
		{
			CloseHandle(g_hInterruptedEvent);
		}

		if (g_hInterruptImport)
		{
			CloseHandle(g_hInterruptImport);
		}

		LOG(0, "GH Injector V%ls detached\n", GH_INJ_VERSIONW);
	}
	
	return TRUE;
}