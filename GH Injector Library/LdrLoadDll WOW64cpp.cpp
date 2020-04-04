#ifdef _WIN64

#include "Injection.h"
#pragma comment (lib, "Psapi.lib")

BYTE LdrLoadDllShell_WOW64[] = { 0x55, 0x8B, 0xEC, 0x56, 0x8B, 0x75, 0x08, 0x85, 0xF6, 0x74, 0x29, 0x8B, 0x46, 0x04, 0x85, 0xC0, 0x74, 0x22, 0x8D, 
	0x4E, 0x14, 0x56, 0x89, 0x4E, 0x10, 0x8D, 0x4E, 0x0C, 0x51, 0x6A, 0x00, 0x6A, 0x00, 0xFF, 0xD0, 0x89, 0x46, 0x08, 0x8B, 0x06, 0xC7, 0x46, 0x04, 0x00,	
	0x00, 0x00, 0x00, 0x5E, 0x5D, 0xC2, 0x04, 0x00, 0x33, 0xC0, 0x5E, 0x5D, 0xC2, 0x04, 0x00 
};

DWORD _LdrLoadDll_WOW64(const wchar_t * szDllFile, HANDLE hTargetProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD & LastError)
{
	size_t size_out = 0;

	LDR_LOAD_DLL_DATA_WOW64 data{ 0 };
	data.pModuleFileName.MaxLength = sizeof(data.Data);
	StringCbLengthW(szDllFile, data.pModuleFileName.MaxLength, &size_out);
	StringCbCopyW(ReCa<wchar_t*>(data.Data), data.pModuleFileName.MaxLength, szDllFile);
	data.pModuleFileName.Length = (WORD)size_out;

	void * pLdrLoadDll = nullptr;
	if (!GetProcAddressEx_WOW64(hTargetProc, TEXT("ntdll.dll"), "LdrLoadDll", pLdrLoadDll))
	{
		LastError = GetLastError();
		return INJ_ERR_LDRLOADDLL_MISSING;
	}

	data.pLdrLoadDll = (DWORD)(ULONG_PTR)pLdrLoadDll;

	BYTE * pArg = ReCa<BYTE*>(VirtualAllocEx(hTargetProc, nullptr, sizeof(LDR_LOAD_DLL_DATA_WOW64) + sizeof(LdrLoadDllShell_WOW64) + 0x10, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pArg)
	{
		LastError = GetLastError();

		return INJ_ERR_CANT_ALLOC_MEM;
	}

	if (!WriteProcessMemory(hTargetProc, pArg, &data, sizeof(LDR_LOAD_DLL_DATA_WOW64), nullptr))
	{
		LastError = GetLastError();

		VirtualFreeEx(hTargetProc, pArg, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	auto * pShell = ReCa<BYTE*>(ALIGN_UP(ReCa<ULONG_PTR>(pArg + sizeof(LDR_LOAD_DLL_DATA_WOW64)), 0x10));
	if (!WriteProcessMemory(hTargetProc, pShell, LdrLoadDllShell_WOW64, sizeof(LdrLoadDllShell_WOW64), nullptr))
	{
		LastError = GetLastError();

		VirtualFreeEx(hTargetProc, pArg, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	DWORD dwOut = 0;
	DWORD dwRet = StartRoutine_WOW64(hTargetProc, MDWD(pShell), MDWD(pArg), Method, (Flags & INJ_THREAD_CREATE_CLOAKED) != 0, LastError, dwOut);
	hOut = (HINSTANCE)(ULONG_PTR)dwOut;

	if(Method != LM_QueueUserAPC)
		VirtualFreeEx(hTargetProc, pArg, 0, MEM_RELEASE);

	return dwRet;
}

#endif