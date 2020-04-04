#include "pch.h"

#include "LdrLoadDll.h"
#pragma comment (lib, "Psapi.lib")

DWORD LdrLoadDll_Shell(LDR_LOAD_DLL_DATA * pData);
DWORD LdrLoadDll_Shell_End();

DWORD _LdrLoadDll(const wchar_t * szDllFile, HANDLE hTargetProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, ERROR_DATA & error_data)
{
	LDR_LOAD_DLL_DATA data{ 0 };
	data.pModuleFileName.MaxLength = sizeof(data.Data);

	size_t size_out = 0;
	HRESULT hr = StringCbLengthW(szDllFile, data.pModuleFileName.MaxLength, &size_out);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		return INJ_ERR_STRINGC_XXX_FAIL;
	}

	hr = StringCbCopyW(ReCa<wchar_t *>(data.Data), data.pModuleFileName.MaxLength, szDllFile);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		return INJ_ERR_STRINGC_XXX_FAIL;
	}

	if (!NT::LdrLoadDll)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return INJ_ERR_LDRLOADDLL_MISSING;
	}

	data.pLdrLoadDll = NT::LdrLoadDll;
	data.pModuleFileName.Length = (WORD)size_out;

	ULONG_PTR ShellSize = (ULONG_PTR)LdrLoadDll_Shell_End - (ULONG_PTR)LdrLoadDll_Shell;

	BYTE * pAllocBase	= ReCa<BYTE*>(VirtualAllocEx(hTargetProc, nullptr, sizeof(LDR_LOAD_DLL_DATA) + ShellSize + 0x10, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	BYTE * pArg			= pAllocBase;
	BYTE * pShell		= ReCa<BYTE*>(ALIGN_UP(ReCa<ULONG_PTR>(pArg) + sizeof(LDR_LOAD_DLL_DATA), 0x10));

	if (!pArg)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		return INJ_ERR_OUT_OF_MEMORY_EXT;
	}

	if (!WriteProcessMemory(hTargetProc, pArg, &data, sizeof(LDR_LOAD_DLL_DATA), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	if (!WriteProcessMemory(hTargetProc, pShell, LdrLoadDll_Shell, ShellSize, nullptr))
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

	if (!ReadProcessMemory(hTargetProc, pAllocBase, &data, sizeof(LDR_LOAD_DLL_DATA), nullptr))
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
		INIT_ERROR_DATA(error_data, (DWORD)data.ntRet);

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

DWORD LdrLoadDll_Shell(LDR_LOAD_DLL_DATA * pData)
{
	if (!pData)
	{
		return INJ_LLDLL_ERR_NO_DATA;
	}
	else if (!pData->pLdrLoadDll)
	{
		return INJ_LLDLL_ERR_INV_DATA;
	}

	pData->pModuleFileName.szBuffer = ReCa<wchar_t*>(pData->Data);
	pData->ntRet = pData->pLdrLoadDll(nullptr, NULL, &pData->pModuleFileName, ReCa<HANDLE*>(&pData->hRet));
	
	if (NT_FAIL(pData->ntRet))
	{
		return INJ_LLDLL_ERR_LL_FAIL;
	}

	return INJ_ERR_SUCCESS;
}

DWORD LdrLoadDll_Shell_End() { return 1; }