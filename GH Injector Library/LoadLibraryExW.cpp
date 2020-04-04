#include "pch.h"

#include "LoadLibraryExW.h"
#pragma comment (lib, "Psapi.lib")

DWORD LoadLibraryExW_Shell(LOAD_LIBRARY_EXW_DATA * pData);
DWORD LoadLibraryExW_Shell_End();

DWORD _LoadLibraryExW(const wchar_t * szDllFile, HANDLE hTargetProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, ERROR_DATA & error_data)
{
	LOAD_LIBRARY_EXW_DATA data{ 0 };
	HRESULT hr = StringCchCopyW(data.szDll, sizeof(data.szDll) / sizeof(wchar_t), szDllFile);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		return INJ_ERR_STRINGC_XXX_FAIL;
	}

	data.pLoadLibraryExW = LoadLibraryExW;

	ULONG_PTR ShellSize = (ULONG_PTR)LoadLibraryExW_Shell_End - (ULONG_PTR)LoadLibraryExW_Shell;
	
	BYTE * pAllocBase	= ReCa<BYTE*>(VirtualAllocEx(hTargetProc, nullptr, sizeof(LOAD_LIBRARY_EXW_DATA) + ShellSize + 0x10, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	BYTE * pArg			= pAllocBase;
	BYTE * pShell		= ReCa<BYTE*>(ALIGN_UP(ReCa<ULONG_PTR>(pArg + sizeof(LOAD_LIBRARY_EXW_DATA)), 0x10));

	if (!pArg)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		return INJ_ERR_OUT_OF_MEMORY_EXT;
	}

	if (!WriteProcessMemory(hTargetProc, pArg, &data, sizeof(LOAD_LIBRARY_EXW_DATA), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	if (!WriteProcessMemory(hTargetProc, pShell, LoadLibraryExW_Shell, ShellSize, nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	DWORD remote_ret = 0;
	DWORD dwRet = StartRoutine(hTargetProc, ReCa<f_Routine>(pShell), pArg, Method, (Flags & INJ_THREAD_CREATE_CLOAKED) != 0, remote_ret, error_data);
	
	if (dwRet != SR_ERR_SUCCESS)
	{
		if (Method != LAUNCH_METHOD::LM_QueueUserAPC && !(Method == LAUNCH_METHOD::LM_HijackThread && dwRet == SR_HT_ERR_REMOTE_TIMEOUT))
		{
			VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);
		}

		return dwRet;
	}

	if (!ReadProcessMemory(hTargetProc, pArg, &data, sizeof(LOAD_LIBRARY_EXW_DATA), nullptr))
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

	hOut = data.hRet;

	return INJ_ERR_SUCCESS;
}

DWORD LoadLibraryExW_Shell(LOAD_LIBRARY_EXW_DATA * pData)
{
	if (!pData)
	{
		return INJ_LLEXW_ERR_NO_DATA;
	}
	else if(!pData->pLoadLibraryExW || !pData->szDll)
	{
		return INJ_LLEXW_ERR_INV_DATA;
	}

	pData->hRet = pData->pLoadLibraryExW(pData->szDll, nullptr, NULL);

	if (!pData->hRet)
	{
		return INJ_LLEXW_ERR_LL_FAIL;
	}

	return INJ_ERR_SUCCESS;
}

DWORD LoadLibraryExW_Shell_End() { return 0; }