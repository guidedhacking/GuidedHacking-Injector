#include "pch.h"

#include "Tools.h"

#if !defined(_WIN64) && defined (DUMP_SHELLCODE)
#include "Manual Mapping.h"
#include "Injection Internal.h"
#endif

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, void * pReserved)
{
	UNREFERENCED_PARAMETER(pReserved);
	
	if (dwReason == DLL_PROCESS_ATTACH)
	{

#if !defined(_WIN64) && defined (DUMP_SHELLCODE)
		HINSTANCE	dummy_instance{ 0 };
		ERROR_DATA	dummy_data{ 0 };
		InjectDLL(nullptr, nullptr, INJECTION_MODE::IM_LoadLibraryExW, LAUNCH_METHOD::LM_NtCreateThreadEx, NULL, dummy_instance, 0, dummy_data);
		MMAP_NATIVE::ManualMap(nullptr, nullptr, LAUNCH_METHOD::LM_NtCreateThreadEx, NULL, dummy_instance, 0, dummy_data);
#endif

		LOG("GH Injector V%ls loaded\nImagebase = %p\n", GH_INJ_VERSIONW, hDll);

		g_hInjMod = hDll;

		wchar_t szRootPathW[MAX_PATH]{ 0 };
		if (!GetOwnModulePathW(szRootPathW, sizeof(szRootPathW) / sizeof(szRootPathW[0])))
		{
			LOG("Couldn't resolve own module path (unicode)\n");

			return FALSE;
		}

		LOG("Rootpath is %ls\n", szRootPathW);

		wchar_t * szWindowsDir = nullptr;

		if (_wdupenv_s(&szWindowsDir, nullptr, L"WINDIR") || !szWindowsDir)
		{
			LOG("Couldn't resolve %%WINDIR%%\n");

			if (szWindowsDir)
			{
				free(szWindowsDir);
			}

			return FALSE;
		}

		g_RootPathW = szRootPathW;

		std::wstring szNtDllNative = szWindowsDir;
		szNtDllNative += L"\\System32\\ntdll.dll";

		LOG("Launching PDB thread(s)\n");

		sym_ntdll_native_ret = std::async(std::launch::async, &SYMBOL_PARSER::Initialize, &sym_ntdll_native, szNtDllNative, g_RootPathW, nullptr, false, true, false);

#ifdef _WIN64
		std::wstring szNtDllWOW64 = szWindowsDir;
		szNtDllWOW64 += L"\\SysWOW64\\ntdll.dll";

		sym_ntdll_wow64_ret = std::async(std::launch::async, &SYMBOL_PARSER::Initialize, &sym_ntdll_wow64, szNtDllWOW64, g_RootPathW, nullptr, false, true, false);
#endif

		free(szWindowsDir);

		LOG("Launching import resolver thread\n");

		import_handler_ret = std::async(std::launch::async, &ResolveImports, std::ref(import_handler_error_data));

		LOG("DllMain exit\n");
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		if (sym_ntdll_native_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
		{
			LOG("ntdll.pdb download thread didn't exit properly.\n");
		}

#ifdef _WIN64
		if (sym_ntdll_wow64_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
		{
			LOG("wntdll.pdb download thread didn't exit properly.\n");
		}		
#endif

		LOG("GH Injector V%ls detached\n", GH_INJ_VERSIONW);
	}
	
	return TRUE;
}