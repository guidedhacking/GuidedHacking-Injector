#include "pch.h"

#include "Tools.h"

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, void * pReserved)
{
	UNREFERENCED_PARAMETER(pReserved);
	
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		LOG("GH Injector V%ls attached at %p\n", GH_INJ_VERSIONW, hDll);

		DisableThreadLibraryCalls(hDll);

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

		g_RootPathA = szRootPathA;
		g_RootPathW = szRootPathW;

		LOG("Rootpath is %s\n", szRootPathA);

#ifdef _WIN64
		sym_ntdll_wow64_ret		= std::async(std::launch::async, &SYMBOL_PARSER::Initialize, &sym_ntdll_wow64,	std::string("C:\\Windows\\SysWOW64\\ntdll.dll"), g_RootPathA, nullptr, false);
		sym_ntdll_native_ret	= std::async(std::launch::async, &SYMBOL_PARSER::Initialize, &sym_ntdll_native, std::string("C:\\Windows\\System32\\ntdll.dll"), g_RootPathA, nullptr, false);
#else
		sym_ntdll_native_ret = std::async(std::launch::async, &SYMBOL_PARSER::Initialize, &sym_ntdll_native, "C:\\Windows\\System32\\ntdll.dll", g_RootPathA, nullptr, false);
#endif
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		LOG("Process detaching\n");
	}
	
	return TRUE;
}