#include "pch.h"

#include "Injection Internal.h"
#include "Manual Mapping.h"

#pragma optimize("", off)

using namespace NATIVE;

DWORD InjectionShell(INJECTION_DATA_INTERNAL * pData);
DWORD InjectionShell_End();

DWORD InjectDLL(const wchar_t * szDllFile, HANDLE hTargetProc, INJECTION_MODE Mode, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, ERROR_DATA & error_data)
{
	LOG("InjectDll called\n");

	if (Mode == INJECTION_MODE::IM_ManualMap)
	{
		LOG("Forwarding call to ManualMap\n");

		return MMAP_NATIVE::ManualMap(szDllFile, hTargetProc, Method, Flags, hOut, error_data);
	}

	INJECTION_DATA_INTERNAL data{ 0 };
	data.Flags	= Flags;
	data.Mode	= Mode;

	size_t len = 0;
	HRESULT hr = StringCbLengthW(szDllFile, sizeof(data.Path), &len);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		return INJ_ERR_STRINGC_XXX_FAIL;
	}

	data.ModuleFileName.Length		= (WORD)(len);
	data.ModuleFileName.MaxLength	= (WORD)(sizeof(data.Path));
	hr = StringCbCopyW(data.Path, sizeof(data.Path), szDllFile);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		return INJ_ERR_STRINGC_XXX_FAIL;
	}

	ULONG_PTR ShellSize		= (ULONG_PTR)InjectionShell_End - (ULONG_PTR)InjectionShell;
	SIZE_T AllocationSize	= sizeof(INJECTION_DATA_INTERNAL) + ShellSize + 0x10;

	BYTE * pAllocBase = ReCa<BYTE *>(VirtualAllocEx(hTargetProc, nullptr, AllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	BYTE * pArg		= pAllocBase;
	BYTE * pShell	= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pArg) + sizeof(INJECTION_DATA_INTERNAL), 0x10));

	LOG("Shellstart = %p\nShellend   = %p\n", InjectionShell, InjectionShell_End);
	LOG("Memory allocated\npArg   = %p\npShell = %p\nAllocationSize = %08X\n", pArg, pShell, (DWORD)AllocationSize);

	if (!pArg)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		return INJ_ERR_OUT_OF_MEMORY_EXT;
	}

	if (!WriteProcessMemory(hTargetProc, pArg, &data, sizeof(INJECTION_DATA_INTERNAL), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	if (!WriteProcessMemory(hTargetProc, pShell, InjectionShell, ShellSize, nullptr))
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

	if (!ReadProcessMemory(hTargetProc, pArg, &data, sizeof(INJECTION_DATA_INTERNAL), nullptr))
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

	hOut = data.hRet;

	return INJ_ERR_SUCCESS;
}

DWORD InjectionShell(INJECTION_DATA_INTERNAL * pData)
{
	if (!pData)
	{
		return INJ_ERR_NO_DATA;
	}
	
	DWORD dwRet = INJ_ERR_SUCCESS;
	INJECTION_FUNCTION_TABLE * f	= &pData->f;
	pData->ModuleFileName.szBuffer	= pData->Path;
	LDR_DATA_TABLE_ENTRY * entry	= nullptr;

	switch (pData->Mode)
	{
		case INJECTION_MODE::IM_LoadLibraryExW:
		{
			pData->hRet = f->pLoadLibraryExW(pData->ModuleFileName.szBuffer, nullptr, NULL);
			if (!pData->hRet)
			{
				pData->LastError = f->pGetLastError();

				dwRet = INJ_ERR_LLEXW_FAILED;
			}
		}
		break;

		case INJECTION_MODE::IM_LdrLoadDll:
		{
			pData->LastError = (DWORD)f->LdrLoadDll(nullptr, NULL, &pData->ModuleFileName, ReCa<HANDLE*>(&pData->hRet));
			if (NT_FAIL(pData->LastError))
			{
				return INJ_ERR_LDRLDLL_FAILED;
			}
		}
		break;

		case INJECTION_MODE::IM_LdrpLoadDll:
		{
			LDRP_LOAD_CONTEXT_FLAGS flags{ 0 };
			LDRP_PATH_SEARCH_CONTEXT ctx{ 0 };
			
			pData->LastError = (DWORD)f->LdrpLoadDll(&pData->ModuleFileName, &ctx, flags, &entry);

			if (NT_FAIL(pData->LastError) || !entry)
			{
				return INJ_ERR_LDRPLDLL_FAILED;
			}

			pData->hRet = ReCa<HINSTANCE>(entry->DllBase);
		}
		break;

		default:
			return INJ_ERR_INVALID_INJ_METHOD;
	}

	if (dwRet != INJ_ERR_SUCCESS)
	{
		return dwRet;
	}

	if (!(pData->Flags & (INJ_UNLINK_FROM_PEB | INJ_FAKE_HEADER | INJ_ERASE_HEADER)))
	{
		return INJ_ERR_SUCCESS;
	}

	if (pData->Flags & INJ_UNLINK_FROM_PEB)
	{

	}

	//peh

	return 0;
}

DWORD InjectionShell_End()
{
	return 0;
}

INJECTION_FUNCTION_TABLE::INJECTION_FUNCTION_TABLE()
{
	WIN32_FUNC_CONSTRUCTOR_INIT(LoadLibraryExW);
	NT_FUNC_CONSTRUCTOR_INIT(LdrLoadDll);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpLoadDll);

	WIN32_FUNC_CONSTRUCTOR_INIT(GetLastError);

	NT_FUNC_CONSTRUCTOR_INIT(LdrLockLoaderLock);
	NT_FUNC_CONSTRUCTOR_INIT(LdrUnlockLoaderLock);

	NT_FUNC_CONSTRUCTOR_INIT(RtlRbRemoveNode);
	NT_FUNC_CONSTRUCTOR_INIT(RtlFreeHeap);

	NT_FUNC_CONSTRUCTOR_INIT(LdrpHeap);
}

#pragma optimize("", on)