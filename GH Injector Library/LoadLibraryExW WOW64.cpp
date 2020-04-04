#include "pch.h"

#ifdef _WIN64

#include "LoadLibraryExW.h"
#pragma comment (lib, "Psapi.lib")

BYTE LoadLibrary_Shell_WOW64[] = 
{
	0x55, 0x8B, 0xEC, 0x56, 0x8B, 0x75, 0x08, 0x85, 0xF6, 0x75, 0x0A, 0xB8, 0x01, 0x00, 0x10, 0x00, 0x5E, 0x5D, 0xC2, 0x04, 0x00, 0x8B, 0x46, 0x04, 0x85, 0xC0, 0x74, 0x23, 0x8D, 0x4E, 0x08, 0x85, 0xC9, 0x74, 0x1C, 0x6A, 
	0x00, 0x6A, 0x00, 0x51, 0xFF, 0xD0, 0x33, 0xC9, 0x89, 0x06, 0x85, 0xC0, 0xBA, 0x03, 0x00, 0x10, 0x00, 0x5E, 0x0F, 0x44, 0xCA, 0x8B, 0xC1, 0x5D, 0xC2, 0x04, 0x00, 0xB8, 0x02, 0x00, 0x10, 0x00, 0x5E, 0x5D, 0xC2, 0x04, 
	0x00
};

DWORD _LoadLibrary_WOW64(const wchar_t * szDllFile, HANDLE hTargetProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, ERROR_DATA & error_data)
{
	LOAD_LIBRARY_EXW_DATA_WOW64 data{ 0 };
	HRESULT hr = StringCchCopyW(data.szDll, sizeof(data.szDll) / sizeof(wchar_t), szDllFile);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		return INJ_ERR_STRINGC_XXX_FAIL;
	}

	if (!REMOTE::LoadLibraryExW_WOW64)
	{
		void * pLoadLibraryExW = nullptr;
		if (!GetProcAddressEx_WOW64(hTargetProc, TEXT("kernel32.dll"), "LoadLibraryExW", pLoadLibraryExW))
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			return INJ_ERR_REMOTEFUNC_MISSING;
		}

		REMOTE::LoadLibraryExW_WOW64 = MDWD(pLoadLibraryExW);
	}
	
	data.pLoadLibraryExW = REMOTE::LoadLibraryExW_WOW64;

	UINT_PTR ShellSize = sizeof(LoadLibrary_Shell_WOW64);

	BYTE * pAllocBase	= ReCa<BYTE*>(VirtualAllocEx(hTargetProc, nullptr, sizeof(LOAD_LIBRARY_EXW_DATA_WOW64) + ShellSize + 0x10, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	BYTE * pArg			= pAllocBase;
	BYTE * pShell		= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pArg + sizeof(LOAD_LIBRARY_EXW_DATA_WOW64)), 0x10));

	if (!pArg)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		return INJ_ERR_OUT_OF_MEMORY_EXT;
	}

	if (!WriteProcessMemory(hTargetProc, pArg, &data, sizeof(LOAD_LIBRARY_EXW_DATA_WOW64), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	if (!WriteProcessMemory(hTargetProc, pShell, LoadLibrary_Shell_WOW64, ShellSize, nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	DWORD remote_ret = 0;
	DWORD dwRet = StartRoutine_WOW64(hTargetProc, MDWD(pShell), MDWD(pArg), Method, (Flags & INJ_THREAD_CREATE_CLOAKED) != 0, remote_ret, error_data);

	if (dwRet != SR_ERR_SUCCESS)
	{
		if (Method != LAUNCH_METHOD::LM_QueueUserAPC && !(Method == LAUNCH_METHOD::LM_HijackThread && dwRet == SR_HT_ERR_REMOTE_TIMEOUT))
		{
			VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);
		}

		return dwRet;
	}

	if (!ReadProcessMemory(hTargetProc, pArg, &data, sizeof(LOAD_LIBRARY_EXW_DATA_WOW64), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		if (Method != LAUNCH_METHOD::LM_QueueUserAPC)
		{
			VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);
		}

		return INJ_ERR_VERIFY_RESULT_FAIL;
	}

	if (Method != LAUNCH_METHOD::LM_QueueUserAPC)
	{
		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);
	}

	if (remote_ret != INJ_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return remote_ret;
	}

	if (!data.hRet)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return INJ_ERR_FAILED_TO_LOAD_DLL;
	}

	hOut = ReCa<HINSTANCE>(MPTR(data.hRet));

	return INJ_ERR_SUCCESS;
}

#endif