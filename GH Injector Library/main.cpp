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

#ifdef DEBUG_INFO
		AllocConsole();

		FILE * pFile = nullptr;
		freopen_s(&pFile, "CONOUT$", "w", stdout);
#endif

		LOG("GH Injector V%ls attached at %p\n", GH_INJ_VERSION, hDll);

		g_hInjMod = hDll;

		char	szRootPathA[MAX_PATH]{ 0 };
		wchar_t szRootPathW[MAX_PATH]{ 0 };

		if (!GetOwnModulePathA(szRootPathA, sizeof(szRootPathA) / sizeof(szRootPathA[0])))
		{
			LOG("Couldn't resolve own module path (ansi)\n");

			return FALSE;
		}
		
		if (!GetOwnModulePathW(szRootPathW, sizeof(szRootPathW) / sizeof(szRootPathW[0])))
		{
			LOG("Couldn't resolve own module path (unicode)\n");

			return FALSE;
		}

		size_t buffer_size = MAX_PATH;
		char * szWindowsDir = new char[buffer_size];

		if (_dupenv_s(&szWindowsDir, &buffer_size, "WINDIR"))
		{
			LOG("Couldn't resolve %%WINDIR%%\n");

			delete[] szWindowsDir;

			return FALSE;
		}

		g_RootPathA = szRootPathA;
		g_RootPathW = szRootPathW;

		LOG("Rootpath is %s\n", szRootPathA);

		std::string szNtDllNative = szWindowsDir;
		szNtDllNative += "\\System32\\ntdll.dll";

		sym_ntdll_native_ret = std::async(std::launch::async, &SYMBOL_PARSER::Initialize, &sym_ntdll_native, szNtDllNative, g_RootPathA, nullptr, false, true);

#ifdef _WIN64
		std::string szNtDllWOW64 = szWindowsDir;
		szNtDllWOW64 += "\\SysWOW64\\ntdll.dll";

		sym_ntdll_wow64_ret = std::async(std::launch::async, &SYMBOL_PARSER::Initialize, &sym_ntdll_wow64, szNtDllWOW64, g_RootPathA, nullptr, false, true);
#endif

		delete[] szWindowsDir;
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		LOG("GH Injector V%ls detaching\n", GH_INJ_VERSION);

		if (sym_ntdll_native_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
		{
			LOG("Attempting to interrupt native ntdll.pdb donwload thread\n");
			sym_ntdll_native.Interrupt();
			if (sym_ntdll_native_ret.wait_for(std::chrono::milliseconds(100)) != std::future_status::ready)
			{
				LOG("Native ntdll pdb download thread didn't exit properly.\n");
			}
		}

#ifdef _WIN64
		if (sym_ntdll_wow64_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
		{
			LOG("Attempting to interrupt wow64 ntdll.pdb donwload thread\n");
			sym_ntdll_wow64.Interrupt();
			if (sym_ntdll_wow64_ret.wait_for(std::chrono::milliseconds(100)) != std::future_status::ready)
			{
				LOG("Wow64 ntdll pdb download thread didn't exit properly.\n");
			}
		}
#endif

		LOG("GH Injector V%ls detached\n", GH_INJ_VERSION);
	}
	
	return TRUE;
}