#include "pch.h"

#ifdef _WIN64

#include "Injection Internal.h"
#include "Manual Mapping.h"

using namespace WOW64;

BYTE InjectionShell_WOW64[] =
{
	0x55, 0x8B, 0xEC, 0x56, 0x8B, 0x75, 0x08, 0x85, 0xF6, 0x75, 0x0A, 0xB8, 0x01, 0x00, 0x20, 0x00, 0x5E, 0x5D, 0xC2, 0x04, 0x00, 0x8B, 0x4E, 0x04, 0x85, 0xC9, 0x75, 0x0A, 0xB8, 0x02, 0x00, 0x20, 0x00, 0x5E, 0x5D, 0xC2,
	0x04, 0x00, 0x8D, 0x46, 0x14, 0x56, 0x89, 0x46, 0x10, 0x8D, 0x46, 0x0C, 0x50, 0x6A, 0x00, 0x6A, 0x00, 0xFF, 0xD1, 0x33, 0xC9, 0x89, 0x46, 0x08, 0x85, 0xC0, 0xBA, 0x03, 0x00, 0x20, 0x00, 0x5E, 0x0F, 0x48, 0xCA, 0x8B,
	0xC1, 0x5D, 0xC2, 0x04, 0x00
};

DWORD InjectDLL_WOW64(const wchar_t * szDllFile, HANDLE hTargetProc, INJECTION_MODE Mode, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, ERROR_DATA & error_data)
{
	if (Mode == INJECTION_MODE::IM_ManualMap)
	{
		return MMAP_WOW64::ManualMap_WOW64(szDllFile, hTargetProc, Method, Flags, hOut, error_data);
	}

	INJECTION_DATA_INTERNAL_WOW64 data{ 0 };
	data.Flags	= Flags;
	data.Mode	= Mode;

	size_t len = 0;
	HRESULT hr = StringCbLengthW(szDllFile, sizeof(data.Path), &len);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		return INJ_ERR_STRINGC_XXX_FAIL;
	}

	if (!data.f.LoadLibraryExW || !data.f.GetLastError)
	{
		HINSTANCE hK32 = GetModuleHandleEx_WOW64(hTargetProc, TEXT("kernel32.dll"));
		GetProcAddressEx_WOW64(hTargetProc, hK32, "LoadLibraryExW", WOW64::LoadLibraryExW_WOW64);
		GetProcAddressEx_WOW64(hTargetProc, hK32, "GetLastError",	WOW64::GetLastError_WOW64);
		data.f.LoadLibraryExW	= WOW64::LoadLibraryExW_WOW64;
		data.f.GetLastError		= WOW64::GetLastError_WOW64;

		if (!data.f.LoadLibraryExW || !data.f.GetLastError)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			return INJ_ERR_GET_PROC_ADDRESS_FAIL;
		}
	}

	data.ModuleFileName.Length		= (WORD)(len - sizeof(wchar_t));
	data.ModuleFileName.MaxLength	= (WORD)(sizeof(data.Path));
	hr = StringCbCopyW(data.Path, sizeof(data.Path), szDllFile);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		return INJ_ERR_STRINGC_XXX_FAIL;
	}

	ULONG_PTR ShellSize		= sizeof(InjectionShell_WOW64);
	SIZE_T AllocationSize	= sizeof(INJECTION_DATA_INTERNAL_WOW64) + ShellSize + 0x10;

	BYTE * pAllocBase = ReCa<BYTE *>(VirtualAllocEx(hTargetProc, nullptr, AllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	BYTE * pArg		= pAllocBase;
	BYTE * pShell	= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pArg + sizeof(INJECTION_DATA_INTERNAL_WOW64)), 0x10));

	if (!pArg)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		return INJ_ERR_OUT_OF_MEMORY_EXT;
	}

	if (!WriteProcessMemory(hTargetProc, pArg, &data, sizeof(INJECTION_DATA_INTERNAL_WOW64), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	if (!WriteProcessMemory(hTargetProc, pShell, InjectionShell_WOW64, ShellSize, nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	DWORD remote_ret = 0;
	DWORD dwRet = StartRoutine_WOW64(hTargetProc, (f_Routine_WOW64)(MDWD(pShell)), MDWD(pArg), Method, (Flags & INJ_THREAD_CREATE_CLOAKED) != 0, remote_ret, error_data);

	if (dwRet != SR_ERR_SUCCESS)
	{
		if (Method != LAUNCH_METHOD::LM_QueueUserAPC && !(Method == LAUNCH_METHOD::LM_HijackThread && dwRet == SR_HT_ERR_REMOTE_TIMEOUT))
		{
			VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);
		}

		return dwRet;
	}

	if (!ReadProcessMemory(hTargetProc, pArg, &data, sizeof(INJECTION_DATA_INTERNAL_WOW64), nullptr))
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
		INIT_ERROR_DATA(error_data, data.LastError);

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

INJECTION_FUNCTION_TABLE_WOW64::INJECTION_FUNCTION_TABLE_WOW64()
{
	WOW64_FUNC_CONSTRUCTOR_INIT(LoadLibraryExW);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrLoadDll);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpLoadDll);

	WOW64_FUNC_CONSTRUCTOR_INIT(GetLastError);

	WOW64_FUNC_CONSTRUCTOR_INIT(LdrLockLoaderLock);
	WOW64_FUNC_CONSTRUCTOR_INIT(LdrUnlockLoaderLock);

	WOW64_FUNC_CONSTRUCTOR_INIT(RtlRbRemoveNode);
	WOW64_FUNC_CONSTRUCTOR_INIT(RtlFreeHeap);

	WOW64_FUNC_CONSTRUCTOR_INIT(LdrpHeap);
}

#endif