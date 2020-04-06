#include "pch.h"

#include "Injection.h"
#include "Symbol Parser.h"

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, void * pReserved)
{
	UNREFERENCED_PARAMETER(pReserved);

	if (dwReason == DLL_PROCESS_ATTACH)
	{
		g_hInjMod = hDll;

		HINSTANCE h_nt_dll = GetModuleHandle(TEXT("ntdll.dll"));
		if (!h_nt_dll)
		{
			return FALSE;
		}

		LOAD_NT_FUNC(NtCreateThreadEx,			h_nt_dll, "NtCreateThreadEx");
		LOAD_NT_FUNC(LdrLoadDll,				h_nt_dll, "LdrLoadDll");
		LOAD_NT_FUNC(NtQueryInformationProcess, h_nt_dll, "NtQueryInformationProcess");
		LOAD_NT_FUNC(NtQuerySystemInformation,	h_nt_dll, "NtQuerySystemInformation");
		LOAD_NT_FUNC(NtQueryInformationThread,	h_nt_dll, "NtQueryInformationThread");

#ifdef _WIN64
		LOAD_NT_FUNC(RtlQueueApcWow64Thread,	h_nt_dll, "RtlQueueApcWow64Thread");
#endif

		char szRootPath[MAX_PATH]{ 0 };
		GetOwnModulePathA(szRootPath, sizeof(szRootPath));
		std::string RootPath = szRootPath;

#ifdef _WIN64
		sym_ntdll_wow64_ret		= std::async(std::launch::async, &SYMBOL_PARSER::Initialize, &sym_ntdll_wow64,	std::string("C:\\Windows\\SysWOW64\\ntdll.dll"), RootPath, nullptr, false);
		sym_ntdll_native_ret	= std::async(std::launch::async, &SYMBOL_PARSER::Initialize, &sym_ntdll_native, std::string("C:\\Windows\\System32\\ntdll.dll"), RootPath, nullptr, false);
#else
		sym_ntdll_native_ret = std::async(std::launch::async, &SYMBOL_PARSER::Initialize, &sym_ntdll_native, "C:\\Windows\\System32\\ntdll.dll", RootPath, nullptr, false);
#endif
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		
	}

#ifdef _DEBUG

	AllocConsole();

	FILE * pFile = nullptr;
	freopen_s(&pFile, "CONOUT$", "w", stdout);

#endif

	return TRUE;
}