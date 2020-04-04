#include "pch.h"

#ifdef _WIN64

#include "LdrpLoadDll.h"
#pragma comment (lib, "Psapi.lib")

BYTE LdrpLoadDll_Shell_WOW64[] =
{
	0x55, 0x8B, 0xEC, 0x56, 0x8B, 0x75, 0x08, 0x85, 0xF6, 0x75, 0x0A, 0xB8, 0x01, 0x00, 0x30, 0x00, 0x5E, 0x5D, 0xC2, 0x04, 0x00, 0x57, 0x8B, 0x7E, 0x04, 0x85, 0xFF, 0x75, 0x0B, 0x5F, 0xB8, 0x02, 0x00, 0x30, 0x00, 0x5E, 
	0x5D, 0xC2, 0x04, 0x00, 0x53, 0x8D, 0x9E, 0x34, 0x02, 0x00, 0x00, 0x53, 0x8D, 0x46, 0x14, 0x6A, 0x00, 0x8D, 0x96, 0x1C, 0x02, 0x00, 0x00, 0x89, 0x46, 0x10, 0x8D, 0x4E, 0x0C, 0xFF, 0xD7, 0x89, 0x46, 0x08, 0x85, 0xC0, 
	0x78, 0x14, 0x8B, 0x03, 0x85, 0xC0, 0x74, 0x0E, 0x8B, 0x40, 0x18, 0x5B, 0x89, 0x06, 0x33, 0xC0, 0x5F, 0x5E, 0x5D, 0xC2, 0x04, 0x00, 0x5B, 0x5F, 0xB8, 0x03, 0x00, 0x30, 0x00, 0x5E, 0x5D, 0xC2, 0x04, 0x00
};

DWORD _LdrpLoadDll_WOW64(const wchar_t * szDllFile, HANDLE hTargetProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, ERROR_DATA & error_data)
{
	LDRP_LOAD_DLL_DATA_WOW64 data{ 0 };
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

	data.pModuleFileName.Length = (WORD)size_out;

	if (!REMOTE::LdrpLoadDll_WOW64)
	{
		HINSTANCE hNTDLL = GetModuleHandleEx_WOW64(hTargetProc, TEXT("ntdll.dll"));
		if (!hNTDLL)
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			return INJ_ERR_REMOTEMODULE_MISSING;
		}

		if (sym_ntdll_wow64_ret.wait_for(std::chrono::milliseconds(100)) != std::future_status::ready)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			return INJ_ERR_SYMBOL_INIT_NOT_DONE;
		}

		DWORD sym_ret = sym_ntdll_wow64_ret.get();
		if (sym_ret != SYMBOL_ERR_SUCCESS)
		{
			INIT_ERROR_DATA(error_data, sym_ret);

			return INJ_ERR_SYMBOL_INIT_FAIL;
		}

		DWORD rva = 0;
		sym_ret = sym_ntdll_wow64.GetSymbolAddress("LdrpLoadDll", rva);
		if (sym_ret != SYMBOL_ERR_SUCCESS || !rva)
		{
			INIT_ERROR_DATA(error_data, sym_ret);

			return INJ_ERR_SYMBOL_GET_FAIL;
		}

		REMOTE::LdrpLoadDll_WOW64 = MDWD(hNTDLL) + rva;
	}

	data.pLdrpLoadDll = REMOTE::LdrpLoadDll_WOW64;

	ULONG_PTR ShellSize = sizeof(LdrpLoadDll_Shell_WOW64);

	BYTE * pAllocBase	= ReCa<BYTE*>(VirtualAllocEx(hTargetProc, nullptr, sizeof(LDRP_LOAD_DLL_DATA_WOW64) + ShellSize + 0x10, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	BYTE * pArg			= pAllocBase;
	BYTE * pShell		= ReCa<BYTE*>(ALIGN_UP(ReCa<ULONG_PTR>(pArg) + sizeof(LDRP_LOAD_DLL_DATA_WOW64), 0x10));

	if (!pArg)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		return INJ_ERR_OUT_OF_MEMORY_EXT;
	}

	if (!WriteProcessMemory(hTargetProc, pArg, &data, sizeof(LDRP_LOAD_DLL_DATA_WOW64), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	if (!WriteProcessMemory(hTargetProc, pShell, LdrpLoadDll_Shell_WOW64, ShellSize, nullptr))
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

	if (!ReadProcessMemory(hTargetProc, pAllocBase, &data, sizeof(LDRP_LOAD_DLL_DATA_WOW64), nullptr))
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

	hOut = ReCa<HINSTANCE>(MPTR(data.hRet));

	return INJ_ERR_SUCCESS;
}

#endif