#include "pch.h"

#include "Injection Internal.h"
#include "Manual Mapping.h"

using namespace NATIVE;

DWORD __declspec(code_seg(".inj_sec$1")) __stdcall InjectionShell(INJECTION_DATA_INTERNAL * pData);
DWORD __declspec(code_seg(".inj_sec$2")) InjectionShell_End();

DWORD InjectDLL(const wchar_t * szDllFile, HANDLE hTargetProc, INJECTION_MODE Mode, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD Timeout, ERROR_DATA & error_data)
{
#if !defined(_WIN64) && defined (DUMP_SHELLCODE)
	auto length = ReCa<BYTE*>(InjectionShell_End) - ReCa<BYTE*>(InjectionShell);
	DumpShellcode(ReCa<BYTE*>(InjectionShell), length, L"InjectionShell_WOW64");
#endif

	LOG("Begin InjectDll\n");

	if (Mode == INJECTION_MODE::IM_ManualMap)
	{
		LOG("Forwarding call to ManualMap\n");

		return MMAP_NATIVE::ManualMap(szDllFile, hTargetProc, Method, Flags, hOut, Timeout, error_data);
	}

	INJECTION_DATA_INTERNAL data{ 0 };
	data.Flags	= Flags;
	data.Mode	= Mode;

	size_t len = 0;
	HRESULT hr = StringCbLengthW(szDllFile, sizeof(data.Path), &len);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		LOG("StringCbLengthW failed: %08X\n", hr);

		return INJ_ERR_STRINGC_XXX_FAIL;
	}

	data.ModuleFileName.Length		= (WORD)len;
	data.ModuleFileName.MaxLength	= (WORD)sizeof(data.Path);

	hr = StringCbCopyW(data.Path, sizeof(data.Path), szDllFile);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		LOG("StringCbCopyW failed: %08X\n", hr);

		return INJ_ERR_STRINGC_XXX_FAIL;
	}

	LOG("Shell data initialized\n");

	ULONG_PTR ShellSize		= ReCa<ULONG_PTR>(InjectionShell_End) - ReCa<ULONG_PTR>(InjectionShell);
	SIZE_T AllocationSize	= sizeof(INJECTION_DATA_INTERNAL) + ShellSize + 0x10;

	BYTE * pAllocBase = ReCa<BYTE*>(VirtualAllocEx(hTargetProc, nullptr, AllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	BYTE * pArg		= pAllocBase;
	BYTE * pShell	= ReCa<BYTE*>(ALIGN_UP(ReCa<ULONG_PTR>(pArg) + sizeof(INJECTION_DATA_INTERNAL), 0x10));

	if (!pArg)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG("VirtualAllocEx failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_OUT_OF_MEMORY_EXT;
	}

	LOG("Shellsize = %IX\nTotal size = %08X\npArg = %p\npShell = %p\n", ShellSize, (DWORD)AllocationSize, pArg, pShell);

	if (!WriteProcessMemory(hTargetProc, pArg, &data, sizeof(INJECTION_DATA_INTERNAL), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG("WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	if (!WriteProcessMemory(hTargetProc, pShell, InjectionShell, ShellSize, nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG("WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	LOG("Shell written to memory\n");

	LOG("Entering StartRoutine\n");

	DWORD remote_ret = 0;
	DWORD dwRet = StartRoutine(hTargetProc, ReCa<f_Routine>(pShell), pArg, Method, (Flags & INJ_THREAD_CREATE_CLOAKED) != 0, remote_ret, Timeout, error_data);

	LOG("Return from StartRoutine\n");

	if (dwRet != SR_ERR_SUCCESS)
	{
		LOG("StartRoutine failed: %08X\n", dwRet);

		if (Method != LAUNCH_METHOD::LM_QueueUserAPC && !(Method == LAUNCH_METHOD::LM_HijackThread && dwRet == SR_HT_ERR_REMOTE_TIMEOUT))
		{
			VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);
		}

		return dwRet;
	}

	LOG("Fetching routine data\n");

	if (!ReadProcessMemory(hTargetProc, pArg, &data, sizeof(INJECTION_DATA_INTERNAL), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG("ReadProcessMemory failed: %08X\n", error_data.AdvErrorCode);

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

		LOG("Shell failed: %08X\n", remote_ret);

		return remote_ret;
	}

	if (!data.hRet)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG("Shell failed\n");

		return INJ_ERR_FAILED_TO_LOAD_DLL;
	}

	LOG("Shell returned successfully\n");

	hOut = data.hRet;

	LOG("Imagebase = %p\n", ReCa<void *>(hOut));

	LOG("End InjectDLL\n");

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".inj_sec$1")) __stdcall InjectionShell(INJECTION_DATA_INTERNAL * pData)
{
	if (!pData)
	{
		return INJ_ERR_NO_DATA;
	}

	DWORD dwRet = INJ_ERR_SUCCESS;

	INJECTION_FUNCTION_TABLE * f	= &pData->f;
	pData->ModuleFileName.szBuffer	= pData->Path;
	
	if (pData->Mode == INJECTION_MODE::IM_LoadLibraryExW)
	{
		pData->hRet = f->pLoadLibraryExW(pData->ModuleFileName.szBuffer, nullptr, NULL);

		if (!pData->hRet)
		{
			pData->LastError = f->pGetLastError();

			dwRet = INJ_ERR_LLEXW_FAILED;
		}
	}
	else if (pData->Mode == INJECTION_MODE::IM_LdrLoadDll)
	{
		pData->LastError = (DWORD)f->LdrLoadDll(nullptr, NULL, &pData->ModuleFileName, ReCa<HANDLE *>(&pData->hRet));

		if (NT_FAIL(pData->LastError))
		{
			return INJ_ERR_LDRLDLL_FAILED;
		}
	}
	else if (pData->Mode == INJECTION_MODE::IM_LdrpLoadDll || pData->Mode == INJECTION_MODE::IM_LdrpLoadDllInternal)
	{
		pData->ModuleFileNameBundle.String.MaxLength = sizeof(pData->ModuleFileNameBundle.StaticBuffer);
		pData->ModuleFileNameBundle.String.szBuffer = pData->ModuleFileNameBundle.StaticBuffer;

		LDRP_LOAD_CONTEXT_FLAGS ctx_flags{ 0 };
		pData->LastError = (DWORD)f->LdrpPreprocessDllName(&pData->ModuleFileName, &pData->ModuleFileNameBundle, nullptr, &ctx_flags);

		if (NT_FAIL(pData->LastError))
		{
			return INJ_ERR_LDRP_PREPROCESS_FAILED;
		}

		LDRP_PATH_SEARCH_CONTEXT ctx{ 0 };
		ctx.OriginalFullDllName = pData->ModuleFileNameBundle.String.szBuffer;

		LDR_DATA_TABLE_ENTRY * entry_out = nullptr;

		if (pData->Mode == INJECTION_MODE::IM_LdrpLoadDll)
		{
			pData->LastError = (DWORD)f->LdrpLoadDll(&pData->ModuleFileNameBundle.String, &ctx, ctx_flags, &entry_out);
		}
		else
		{
			ULONG_PTR unknown = 0;
			pData->LastError = (DWORD)f->LdrpLoadDllInternal(&pData->ModuleFileNameBundle.String, &ctx, ctx_flags, 4, nullptr, nullptr, &entry_out, &unknown);
		}

		if (NT_FAIL(pData->LastError) || !entry_out)
		{
			return INJ_ERR_LDRPLDLL_FAILED;
		}

		pData->hRet = ReCa<HINSTANCE>(entry_out->DllBase);
	}
	else
	{
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

	PEB * pPEB = nullptr;
	LDR_DATA_TABLE_ENTRY * pEntry = nullptr;

#ifdef  _WIN64
	pPEB = ReCa<PEB*>(__readgsqword(0x60));
#else
	pPEB = ReCa<PEB*>(__readfsdword(0x30));
#endif 

	if (!pPEB)
	{
		return INJ_ERR_CANT_GET_PEB;
	}

	if (!pPEB->Ldr || !pPEB->Ldr->InLoadOrderModuleListHead.Flink)
	{
		return INJ_ERR_INVALID_PEB_DATA;
	}

	if ((pData->Flags & (INJ_FAKE_HEADER | INJ_ERASE_HEADER)))
	{
		auto * dos_header	= ReCa<IMAGE_DOS_HEADER*>(ReCa<BYTE*>(pData->hRet));
		auto * nt_headers	= ReCa<IMAGE_NT_HEADERS*>(ReCa<BYTE*>(pData->hRet) + dos_header->e_lfanew);
		SIZE_T header_size	= nt_headers->OptionalHeader.SizeOfHeaders;

		HANDLE hProc = MPTR(-1);

		ULONG old_access	= NULL;
		void * base			= ReCa<void*>(pData->hRet);

		pData->LastError = (DWORD)f->NtProtectVirtualMemory(hProc, &base, &header_size, PAGE_EXECUTE_READWRITE, &old_access);

		if (NT_FAIL(pData->LastError))
		{
			return INJ_ERR_UPDATE_PROTECTION_FAILED;
		}

		if (pData->Flags & INJ_ERASE_HEADER)
		{
			f->RtlZeroMemory(base, header_size);
		}
		else if (pData->Flags & INJ_FAKE_HEADER)
		{
			auto * ntdll_ldr = ReCa<LDR_DATA_TABLE_ENTRY*>(pPEB->Ldr->InLoadOrderModuleListHead.Flink->Flink);

			if (!ntdll_ldr)
			{
				return INJ_ERR_INVALID_PEB_DATA;
			}

			f->memmove(base, ntdll_ldr->DllBase, header_size);
		}

		pData->LastError = (DWORD)f->NtProtectVirtualMemory(hProc, &base, &header_size, old_access, &old_access);

		if (NT_FAIL(pData->LastError))
		{
			return INJ_ERR_UPDATE_PROTECTION_FAILED;
		}
	}

	if (pData->Flags & INJ_UNLINK_FROM_PEB)
	{
		LIST_ENTRY * pHead		= &pPEB->Ldr->InLoadOrderModuleListHead;
		LIST_ENTRY * pCurrent	= pHead->Flink;

		while (pCurrent != pHead)
		{
			pEntry = ReCa<LDR_DATA_TABLE_ENTRY*>(pCurrent);

			if (pEntry->DllBase == pData->hRet)
			{
				break;
			}

			pCurrent = pCurrent->Flink;
		}

		if (!pEntry)
		{
			return INJ_ERR_CANT_FIND_MOD_PEB;
		}

		pEntry->InLoadOrderLinks.Flink->Blink			= pEntry->InLoadOrderLinks.Blink;
		pEntry->InLoadOrderLinks.Blink->Flink			= pEntry->InLoadOrderLinks.Flink;
		pEntry->InInitializationOrderLinks.Flink->Blink = pEntry->InInitializationOrderLinks.Blink;
		pEntry->InInitializationOrderLinks.Blink->Flink = pEntry->InInitializationOrderLinks.Flink;
		pEntry->InMemoryOrderLinks.Flink->Blink			= pEntry->InMemoryOrderLinks.Blink;
		pEntry->InMemoryOrderLinks.Blink->Flink			= pEntry->InMemoryOrderLinks.Flink;
		pEntry->HashLinks.Flink->Blink					= pEntry->HashLinks.Blink;
		pEntry->HashLinks.Blink->Flink					= pEntry->HashLinks.Flink;

		f->RtlRbRemoveNode(f->LdrpModuleBaseAddressIndex,	&pEntry->BaseAddressIndexNode);
		f->RtlRbRemoveNode(f->LdrpMappingInfoIndex,			&pEntry->MappingInfoIndexNode);

		f->RtlZeroMemory(pEntry->BaseDllName.szBuffer, pEntry->BaseDllName.MaxLength);
		f->RtlZeroMemory(pEntry->FullDllName.szBuffer, pEntry->FullDllName.MaxLength);

		LDR_DDAG_NODE * pDDagNode = pEntry->DdagNode;

		f->RtlZeroMemory(pEntry, sizeof(LDR_DATA_TABLE_ENTRY));
		f->RtlZeroMemory(pDDagNode, sizeof(LDR_DDAG_NODE));
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".inj_sec$2")) InjectionShell_End()
{
	return 0;
}

INJECTION_FUNCTION_TABLE::INJECTION_FUNCTION_TABLE()
{
	WIN32_FUNC_CONSTRUCTOR_INIT(LoadLibraryExW);
	NT_FUNC_CONSTRUCTOR_INIT(LdrLoadDll);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpLoadDll);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpLoadDllInternal);

	NT_FUNC_CONSTRUCTOR_INIT(LdrpPreprocessDllName);

	WIN32_FUNC_CONSTRUCTOR_INIT(GetLastError);

	NT_FUNC_CONSTRUCTOR_INIT(memmove);
	NT_FUNC_CONSTRUCTOR_INIT(RtlZeroMemory);
	NT_FUNC_CONSTRUCTOR_INIT(RtlFreeHeap);

	NT_FUNC_CONSTRUCTOR_INIT(RtlRbRemoveNode);
	
	NT_FUNC_CONSTRUCTOR_INIT(NtProtectVirtualMemory);

	NT_FUNC_CONSTRUCTOR_INIT(LdrpModuleBaseAddressIndex);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpMappingInfoIndex);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpHeap);
}