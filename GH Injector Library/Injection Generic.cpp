#include "pch.h"

#include "Injection Internal.h"

#define UNLINK_IF(e)			\
if (e.Flink && e.Blink)			\
{								\
	e.Flink->Blink = e.Blink;	\
	e.Blink->Flink = e.Flink;	\
}

using namespace NATIVE;

DWORD __declspec(code_seg(".inj_sec$1")) __stdcall InjectionShell(INJECTION_DATA_MAPPED * pData);
DWORD __declspec(code_seg(".inj_sec$2")) INJ_SEC_END();

DWORD InjectDLL(const INJECTION_SOURCE & Source, HANDLE hTargetProc, INJECTION_MODE Mode, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD Timeout, ERROR_DATA & error_data)
{
#if !defined(_WIN64) && defined (DUMP_SHELLCODE)
	DUMP_WOW64(InjectionShell, INJ_SEC_END);

	return INJ_ERR_SHELLCODE_DUMPED;
#endif

	LOG(1, "Begin InjectDll\n");

	if (Mode == INJECTION_MODE::IM_ManualMap)
	{
		LOG(1, "Forwarding call to ManualMap\n");

		return MMAP_NATIVE::ManualMap(Source, hTargetProc, Method, Flags, hOut, Timeout, error_data);
	}

	INJECTION_DATA_MAPPED data{ 0 };
	data.Flags			= Flags;
	data.Mode			= Mode;
	data.OSVersion		= GetOSVersion();
	data.OSBuildNumber	= GetOSBuildVersion();

	size_t len = Source.DllPath.length();
	size_t max_len = sizeof(data.Path) / sizeof(wchar_t);
	if (len > max_len)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "Path too long: %d characters, buffer size: %d\n", len, max_len);

		return INJ_ERR_STRING_TOO_LONG;
	}
		
	data.ModuleFileName.Length		= (WORD)(len * sizeof(wchar_t));
	data.ModuleFileName.MaxLength	= (WORD)sizeof(data.Path);
	Source.DllPath.copy(data.Path, Source.DllPath.length());

	LOG(1, "Shell data initialized\n");

	ULONG_PTR ShellSize		= ReCa<ULONG_PTR>(INJ_SEC_END) - ReCa<ULONG_PTR>(InjectionShell);
	ULONG_PTR VEHShellSize	= ReCa<ULONG_PTR>(VEH_SEC_END) - ReCa<ULONG_PTR>(VectoredHandlerShell);

	if (!(Flags & INJ_UNLINK_FROM_PEB))
	{
		VEHShellSize = 0;
	}

	SIZE_T AllocationSize	= sizeof(INJECTION_DATA_MAPPED) + ShellSize + BASE_ALIGNMENT;
	BYTE * pAllocBase		= ReCa<BYTE *>(VirtualAllocEx(hTargetProc, nullptr, AllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

	BYTE * pArg			= pAllocBase;
	BYTE * pShell		= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pArg) + sizeof(INJECTION_DATA_MAPPED), BASE_ALIGNMENT));
	BYTE * pVEHShell	= nullptr;

	if (!pArg)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "VirtualAllocEx failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_OUT_OF_MEMORY_EXT;
	}

	if(VEHShellSize)
	{
		pVEHShell = ReCa<BYTE *>(VirtualAllocEx(hTargetProc, nullptr, VEHShellSize + sizeof(VEH_SHELL_DATA) + BASE_ALIGNMENT, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

		if (!pVEHShell)
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(1, "VirtualAllocEx failed: %08X\n", error_data.AdvErrorCode);

			VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

			return INJ_ERR_OUT_OF_MEMORY_EXT;
		}

		data.pVEHShell		= pVEHShell;
		data.VEHShellSize	= MDWD(VEHShellSize);
	}	

	LOG(2, "Shellsize  = %08X\n", MDWD(ShellSize));
	LOG(2, "Total size = %08X\n", MDWD(AllocationSize));
	LOG(2, "pArg       = %p\n", pArg);
	LOG(2, "pShell     = %p\n", pShell);

	if (VEHShellSize)
	{
		LOG(2, "pVEHShell   = %p\n", pVEHShell);
	}

	if (!WriteProcessMemory(hTargetProc, pArg, &data, sizeof(INJECTION_DATA_MAPPED), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		if (pVEHShell)
		{
			VirtualFreeEx(hTargetProc, pVEHShell, 0, MEM_RELEASE);
		}

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	if (!WriteProcessMemory(hTargetProc, pShell, InjectionShell, ShellSize, nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		if (pVEHShell)
		{
			VirtualFreeEx(hTargetProc, pVEHShell, 0, MEM_RELEASE);
		}

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	LOG(1, "Shell written to memory\n");

	if (VEHShellSize)
	{
		if (!WriteProcessMemory(hTargetProc, pVEHShell, VectoredHandlerShell, VEHShellSize, nullptr))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(1, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

			if (pVEHShell)
			{
				VirtualFreeEx(hTargetProc, pVEHShell, 0, MEM_RELEASE);
			}

			VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

			return INJ_ERR_WPM_FAIL;
		}

		LOG(1, "VEHShell written to memory\n");
	}

	LOG(1, "Entering StartRoutine\n");

	if (Flags & INJ_THREAD_CREATE_CLOAKED)
	{
		Flags |= (INJ_CTF_FAKE_START_ADDRESS | INJ_CTF_HIDE_FROM_DEBUGGER);
	}

	DWORD remote_ret = 0;
	DWORD dwRet = StartRoutine(hTargetProc, ReCa<f_Routine>(pShell), pArg, Method, Flags, remote_ret, Timeout, error_data);

	LOG(1, "Return from StartRoutine\n");

	if (dwRet != SR_ERR_SUCCESS)
	{
		LOG(1, "StartRoutine failed: %08X\n", dwRet);

		if (Method != LAUNCH_METHOD::LM_QueueUserAPC && !(Method == LAUNCH_METHOD::LM_HijackThread && dwRet == SR_HT_ERR_REMOTE_TIMEOUT))
		{
			if (pVEHShell)
			{
				VirtualFreeEx(hTargetProc, pVEHShell, 0, MEM_RELEASE);
			}

			VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);
		}

		return dwRet;
	}

	LOG(1, "Fetching routine data\n");

	if (!ReadProcessMemory(hTargetProc, pArg, &data, sizeof(INJECTION_DATA_MAPPED), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "ReadProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		if (Method != LAUNCH_METHOD::LM_QueueUserAPC)
		{
			if (pVEHShell)
			{
				VirtualFreeEx(hTargetProc, pVEHShell, 0, MEM_RELEASE);
			}

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

		LOG(1, "Shell failed: %08X\n", remote_ret);

		return remote_ret;
	}

	if (!data.hRet)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "Shell failed\n");

		return INJ_ERR_FAILED_TO_LOAD_DLL;
	}

	LOG(1, "Shell returned successfully\n");

	hOut = data.hRet;

	LOG(1, "Imagebase = %p\n", ReCa<void *>(hOut));

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".inj_sec$1")) __stdcall InjectionShell(INJECTION_DATA_MAPPED * pData)
{
	if (!pData)
	{
		return INJ_ERR_NO_DATA;
	}

	INJECTION_FUNCTION_TABLE * f = &pData->f;
	pData->ModuleFileName.szBuffer = pData->Path;

	if (pData->Mode == INJECTION_MODE::IM_LoadLibraryExW)
	{
		pData->hRet = f->pLoadLibraryExW(pData->ModuleFileName.szBuffer, nullptr, NULL);

		if (!pData->hRet)
		{
			pData->LastError = f->pGetLastError();

			return INJ_ERR_LLEXW_FAILED;
		}
	}
	else if (pData->Mode == INJECTION_MODE::IM_LdrLoadDll)
	{
		ULONG Flags = NULL;

		LDR_SEARCH_PATH optPath{ 0 };
		if (pData->OSVersion == g_Win7)
		{
			optPath.szSearchPath = f->LdrpDefaultPath->szBuffer;
		}
		else
		{
			optPath.NoPath = TRUE;
		}

		pData->LastError = (DWORD)f->LdrLoadDll(optPath, &Flags, &pData->ModuleFileName, ReCa<HANDLE *>(&pData->hRet));

		if (NT_FAIL(pData->LastError))
		{
			return INJ_ERR_LDRLDLL_FAILED;
		}
	}
	else if (pData->OSVersion >= g_Win10)
	{
		LDR_DATA_TABLE_ENTRY * entry_out = nullptr;
		LDRP_LOAD_CONTEXT_FLAGS ctx_flags{ 0 };

		LDRP_PATH_SEARCH_CONTEXT * ctx = &pData->SearchPathContext;
		ctx->OriginalFullDllName = pData->Path;

		if (pData->OSBuildNumber == g_Win10_1511)
		{
			ReCa<LDRP_PATH_SEARCH_CONTEXT_1511 *>(ctx)->OriginalFullDllName = pData->Path;
			ctx->OriginalFullDllName = nullptr;
		}

		if (pData->Mode == INJECTION_MODE::IM_LdrpLoadDll)
		{
			if (pData->OSBuildNumber <= g_Win10_1803)
			{
				auto _LdrpLoadDll = ReCa<f_LdrpLoadDll_1507>(f->LdrpLoadDll);
				pData->LastError = _LdrpLoadDll(&pData->ModuleFileName, ctx, ctx_flags, TRUE, ReCa<LDR_DATA_TABLE_ENTRY_WIN10 **>(&entry_out));
			}
			else
			{
				pData->LastError = f->LdrpLoadDll(&pData->ModuleFileName, ctx, ctx_flags, &entry_out);
			}
		}
		else
		{
			pData->ModuleFileNameBundle.String.szBuffer = pData->ModuleFileNameBundle.StaticBuffer;

			pData->LastError = (DWORD)f->LdrpPreprocessDllName(&pData->ModuleFileName, &pData->ModuleFileNameBundle, nullptr, &ctx_flags);

			if (NT_FAIL(pData->LastError))
			{
				return INJ_ERR_LDRP_PREPROCESS_FAILED;
			}

			NTSTATUS nt_out = 0;

			if (pData->OSBuildNumber >= g_Win11_21H2) //Win11 prototype has an additional argument
			{
				auto _LdrpLoadDllInternal = ReCa<f_LdrpLoadDllInternal_WIN11>(f->LdrpLoadDllInternal);
				_LdrpLoadDllInternal(&pData->ModuleFileNameBundle.String, ctx, ctx_flags, 4, nullptr, nullptr, ReCa<LDR_DATA_TABLE_ENTRY_WIN11 **>(&entry_out), &nt_out, 0);
			}
			else
			{
				f->LdrpLoadDllInternal(&pData->ModuleFileNameBundle.String, ctx, ctx_flags, 4, nullptr, nullptr, ReCa<LDR_DATA_TABLE_ENTRY_WIN10 **>(&entry_out), &nt_out);
			}

			if (NT_FAIL(nt_out))
			{
				pData->LastError = (DWORD)nt_out;

				return INJ_ERR_LDRPLDLLINTERNAL_FAILED;
			}
		}

		if (!entry_out)
		{
			return INJ_ERR_LDR_ENTRY_IS_NULL;
		}
		else
		{
			f->LdrpDereferenceModule(entry_out);
		}

		pData->hRet = ReCa<HINSTANCE>(entry_out->DllBase);
	}
	else if (pData->OSVersion == g_Win81 && pData->Mode == INJECTION_MODE::IM_LdrpLoadDll)
	{
		auto _LdrpLoadDll = ReCa<f_LdrpLoadDll_WIN81>(f->LdrpLoadDll);

		LDRP_PATH_SEARCH_CONTEXT_WIN81 ctx{ 0 };
		ctx.OriginalFullDllName = pData->ModuleFileName.szBuffer;

		LDRP_LOAD_CONTEXT_FLAGS ctx_flags{ 0 };

		LDR_DATA_TABLE_ENTRY_WIN81	* entry_out = nullptr;
		LDR_DDAG_NODE_WIN81			* ddag_out	= nullptr;

		pData->LastError = (DWORD)_LdrpLoadDll(&pData->ModuleFileName, &ctx, ctx_flags, TRUE, &entry_out, &ddag_out);

		if (NT_FAIL(pData->LastError))
		{
			return INJ_ERR_LDRPLDLL_FAILED;
		}

		if (!entry_out)
		{
			return INJ_ERR_LDR_ENTRY_IS_NULL;
		}

		pData->hRet = ReCa<HINSTANCE>(entry_out->DllBase);
	}
	else if (pData->OSVersion == g_Win8 && pData->Mode == INJECTION_MODE::IM_LdrpLoadDll)
	{
		auto _LdrpLoadDll = ReCa<f_LdrpLoadDll_WIN8>(f->LdrpLoadDll);

		LDRP_PATH_SEARCH_CONTEXT_WIN8 ctx{ 0 };
		ctx.OriginalFullDllName = pData->ModuleFileName.szBuffer;
		ctx.unknown2 = TRUE;

		LDRP_LOAD_CONTEXT_FLAGS ctx_flags{ 0 };

		LDR_DATA_TABLE_ENTRY_WIN8	* entry_out = nullptr;
		LDR_DDAG_NODE_WIN8			* ddag_out	= nullptr;

		pData->LastError = (DWORD)_LdrpLoadDll(&pData->ModuleFileName, &ctx, ctx_flags, TRUE, &entry_out, &ddag_out);

		if (NT_FAIL(pData->LastError))
		{
			return INJ_ERR_LDRPLDLL_FAILED;
		}

		if (!entry_out)
		{
			return INJ_ERR_LDR_ENTRY_IS_NULL;
		}

		pData->hRet = ReCa<HINSTANCE>(entry_out->DllBase);
	}
	else if (pData->OSVersion == g_Win7 && pData->Mode == INJECTION_MODE::IM_LdrpLoadDll)
	{
		auto _LdrpLoadDll = ReCa<f_LdrpLoadDll_WIN7>(f->LdrpLoadDll);

		LDRP_LOAD_CONTEXT_FLAGS ctx_flags{ 0 };

		LDR_DATA_TABLE_ENTRY_WIN7 * entry_out = nullptr;

		pData->LastError = (DWORD)_LdrpLoadDll(&pData->ModuleFileName, f->LdrpDefaultPath, ctx_flags, TRUE, nullptr, &entry_out);

		if (NT_FAIL(pData->LastError))
		{
			return INJ_ERR_LDRPLDLL_FAILED;
		}

		if (!entry_out)
		{
			return INJ_ERR_LDR_ENTRY_IS_NULL;
		}

		pData->hRet = ReCa<HINSTANCE>(entry_out->DllBase);
	}
	else
	{
		return INJ_ERR_INVALID_INJ_METHOD;
	}
	
	if (!(pData->Flags & (INJ_UNLINK_FROM_PEB | INJ_FAKE_HEADER | INJ_ERASE_HEADER)))
	{
		return INJ_ERR_SUCCESS;
	}	

	PEB						* pPEB		= nullptr;
	LDR_DATA_TABLE_ENTRY	* pEntry	= nullptr;

#ifdef  _WIN64
	pPEB = ReCa<PEB *>(__readgsqword(0x60));
#else
	pPEB = ReCa<PEB *>(__readfsdword(0x30));
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
		auto * dos_header	= ReCa<IMAGE_DOS_HEADER *>(ReCa<BYTE *>(pData->hRet));
		auto * nt_headers	= ReCa<IMAGE_NT_HEADERS *>(ReCa<BYTE *>(pData->hRet) + dos_header->e_lfanew);
		SIZE_T header_size	= nt_headers->OptionalHeader.SizeOfHeaders;

		HANDLE hProc = NtCurrentProcess();

		ULONG old_access	= NULL;
		void * base			= ReCa<void *>(pData->hRet);

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
			auto * ntdll_ldr = ReCa<LDR_DATA_TABLE_ENTRY *>(pPEB->Ldr->InLoadOrderModuleListHead.Flink->Flink);

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
			if (ReCa<LDR_DATA_TABLE_ENTRY *>(pCurrent)->DllBase == pData->hRet)
			{
				pEntry = ReCa<LDR_DATA_TABLE_ENTRY *>(pCurrent);

				break;
			}

			pCurrent = pCurrent->Flink;
		}

		if (!pEntry)
		{
			return INJ_ERR_CANT_FIND_MOD_PEB;
		}
		
		auto * veh_shell_data = ReCa<VEH_SHELL_DATA *>(ALIGN_UP(pData->pVEHShell + pData->VEHShellSize, BASE_ALIGNMENT));
		
		veh_shell_data->ImgBase		= ReCa<ULONG_PTR>(pEntry->DllBase);
		veh_shell_data->ImgSize		= pEntry->SizeOfImage;
		veh_shell_data->OSVersion	= pData->OSVersion;
		veh_shell_data->LdrpInvertedFunctionTable	= f->LdrpInvertedFunctionTable;
		veh_shell_data->LdrProtectMrdata			= f->LdrProtectMrdata;

		bool veh_shell_fixed = FindAndReplacePtr(pData->pVEHShell, pData->VEHShellSize, VEHDATASIG, ReCa<UINT_PTR>(veh_shell_data));

		if (veh_shell_fixed)
		{
			f->RtlAddVectoredExceptionHandler(0, ReCa<PVECTORED_EXCEPTION_HANDLER>(pData->pVEHShell));
		}

		UNLINK_IF(pEntry->InLoadOrderLinks);
		UNLINK_IF(pEntry->InInitializationOrderLinks);
		UNLINK_IF(pEntry->InMemoryOrderLinks);	
		UNLINK_IF(pEntry->HashLinks);

		size_t ldr_size		= sizeof(LDR_DATA_TABLE_ENTRY);
		size_t ddag_size	= sizeof(LDR_DDAG_NODE);
		void * pDDag		= nullptr;

		if (pData->OSVersion == g_Win7)
		{
			auto * pEntry7 = ReCa<LDR_DATA_TABLE_ENTRY_WIN7 *>(pEntry);
			UNLINK_IF(pEntry7->ForwarderLinks);
			UNLINK_IF(pEntry7->ServiceTagLinks);
			UNLINK_IF(pEntry7->StaticLinks);

			ldr_size = sizeof(LDR_DATA_TABLE_ENTRY_WIN7);
		}
		else
		{
			f->RtlRbRemoveNode(f->LdrpModuleBaseAddressIndex,	&pEntry->BaseAddressIndexNode);
			f->RtlRbRemoveNode(f->LdrpMappingInfoIndex,			&pEntry->MappingInfoIndexNode);

			if (pData->OSVersion == g_Win8)
			{
				ldr_size	= sizeof(LDR_DATA_TABLE_ENTRY_WIN8);
				ddag_size	= sizeof(LDR_DDAG_NODE_WIN8);
			}
			else if (pData->OSVersion == g_Win81)
			{
				ldr_size	= sizeof(LDR_DATA_TABLE_ENTRY_WIN81);
				ddag_size	= sizeof(LDR_DDAG_NODE_WIN81);
			}
			else if (pData->OSVersion >= g_Win10) //Win10 or Win11, same OSVersion...
			{
				if (pData->OSBuildNumber <= g_Win10_1511) //1507 - 1511
				{
					ldr_size = offsetof(LDR_DATA_TABLE_ENTRY_WIN10, DependentLoadFlags);
				}
				else if (pData->OSBuildNumber <= g_Win10_1607) //1607
				{
					ldr_size = offsetof(LDR_DATA_TABLE_ENTRY_WIN10, SigningLevel);
				}
				else if (pData->OSBuildNumber <= g_Win10_21H2) //1703 - 21H2 (Win10)
				{
					ldr_size	= sizeof(LDR_DATA_TABLE_ENTRY_WIN10);
					ddag_size	= sizeof(LDR_DDAG_NODE_WIN10);
				}
				else //21H2+ (Win11)
				{
					ldr_size	= sizeof(LDR_DATA_TABLE_ENTRY_WIN11);
					ddag_size	= sizeof(LDR_DDAG_NODE_WIN11);
				}
			}			

			pDDag = pEntry->DdagNode;
		}

		f->RtlZeroMemory(pEntry->BaseDllName.szBuffer, pEntry->BaseDllName.MaxLength);
		f->RtlZeroMemory(pEntry->FullDllName.szBuffer, pEntry->FullDllName.MaxLength);

		f->RtlZeroMemory(pEntry, ldr_size);

		if (pDDag)
		{
			f->RtlZeroMemory(pDDag, ddag_size);
		}
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".inj_sec$2")) INJ_SEC_END()
{
	return 1338;
}

INJECTION_FUNCTION_TABLE::INJECTION_FUNCTION_TABLE()
{
	WIN32_FUNC_CONSTRUCTOR_INIT(LoadLibraryExW);
	NT_FUNC_CONSTRUCTOR_INIT(LdrLoadDll);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpLoadDll);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpLoadDllInternal);

	NT_FUNC_CONSTRUCTOR_INIT(LdrpPreprocessDllName);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpDereferenceModule);

	WIN32_FUNC_CONSTRUCTOR_INIT(GetLastError);

	NT_FUNC_CONSTRUCTOR_INIT(memmove);
	NT_FUNC_CONSTRUCTOR_INIT(RtlZeroMemory);

	NT_FUNC_CONSTRUCTOR_INIT(RtlRbRemoveNode);
	
	NT_FUNC_CONSTRUCTOR_INIT(NtProtectVirtualMemory);

	NT_FUNC_CONSTRUCTOR_INIT(RtlAddVectoredExceptionHandler);
	NT_FUNC_CONSTRUCTOR_INIT(LdrProtectMrdata);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpInvertedFunctionTable);

	NT_FUNC_CONSTRUCTOR_INIT(LdrpModuleBaseAddressIndex);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpMappingInfoIndex);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpDefaultPath);
}