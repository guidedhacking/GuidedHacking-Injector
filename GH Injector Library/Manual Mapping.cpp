#include "pch.h"

#include "Manual Mapping.h"
#pragma comment (lib, "Psapi.lib")

DWORD ManualMapping_Shell(MANUAL_MAPPING_DATA * pData);
DWORD ManualMapping_Shell_End();

MANUAL_MAPPER::~MANUAL_MAPPER()
{
	if (pRawData)
	{
		delete[] pRawData;
	}

	if (pLocalImageBase)
	{
		VirtualFree(pLocalImageBase, 0, MEM_RELEASE);
	}

	if (pAllocationBase && !bKeepTarget)
	{
		VirtualFreeEx(hTargetProcess, pAllocationBase, 0, MEM_RELEASE);
	}
}

DWORD MANUAL_MAPPER::AllocateMemory(ERROR_DATA & error_data)
{
	pLocalImageBase = ReCa<BYTE*>(VirtualAlloc(nullptr, ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pLocalImageBase)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		return INJ_ERR_OUT_OF_MEMORY_INT;
	}

	if (Flags & INJ_MM_SHIFT_MODULE)
	{
		srand(GetTickCount64() & 0xFFFFFFFF);
		ShiftOffset = ALIGN_UP(rand() % 0x1000 + 0x100, 0x10);
	}

	DWORD ShellcodeSize = (DWORD)((ULONG_PTR)ManualMapping_Shell_End - (ULONG_PTR)ManualMapping_Shell);

	AllocationSize = ShiftOffset + ImageSize + sizeof(MANUAL_MAPPING_DATA) + ShellcodeSize;

	if(Flags & INJ_MM_SHIFT_MODULE)
	{
		pAllocationBase = ReCa<BYTE*>(VirtualAllocEx(hTargetProcess, nullptr, AllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (!pAllocationBase)
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			return INJ_ERR_OUT_OF_MEMORY_EXT;
		}
	}
	else
	{
		pAllocationBase = ReCa<BYTE*>(VirtualAllocEx(hTargetProcess, ReCa<void*>(pLocalOptionalHeader->ImageBase), AllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (!pAllocationBase)
		{
			pAllocationBase = ReCa<BYTE*>(VirtualAllocEx(hTargetProcess, nullptr, AllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
			if (!pAllocationBase)
			{
				INIT_ERROR_DATA(error_data, GetLastError());

				return INJ_ERR_OUT_OF_MEMORY_EXT;
			}
		}
	}

	pTargetImageBase	= pAllocationBase		+ ShiftOffset;
	pManualMappingData	= pTargetImageBase		+ ImageSize;
	pShellcode			= pManualMappingData	+ sizeof(MANUAL_MAPPING_DATA);
	
	return INJ_ERR_SUCCESS;
}

DWORD MANUAL_MAPPER::CopyData(ERROR_DATA & error_data)
{
	memcpy(pLocalImageBase, pRawData, pLocalOptionalHeader->SizeOfHeaders);

	auto * pCurrentSectionHeader = IMAGE_FIRST_SECTION(pLocalNtHeaders);
	for (UINT i = 0; i != pLocalFileHeader->NumberOfSections; ++i, ++pCurrentSectionHeader)
	{
		if (pCurrentSectionHeader->SizeOfRawData)
		{
			memcpy(pLocalImageBase + pCurrentSectionHeader->VirtualAddress, pRawData + pCurrentSectionHeader->PointerToRawData, pCurrentSectionHeader->SizeOfRawData);
		}
	}
	
	if (Flags & INJ_MM_SHIFT_MODULE)
	{
		DWORD * pJunk = new DWORD[ShiftOffset / sizeof(DWORD)];
		if (!pJunk)
		{
			return INJ_ERR_OUT_OF_MEMORY_NEW;
		}

		DWORD SuperJunk = GetTickCount64() & 0xFFFFFFFF;

		for (UINT i = 0; i < ShiftOffset / sizeof(DWORD); ++i)
		{
			pJunk[i] = SuperJunk;
			SuperJunk ^= (i << (i % 32));
			SuperJunk -= 0x11111111;
		}

		WriteProcessMemory(hTargetProcess, pAllocationBase, pJunk, ShiftOffset, nullptr);

		delete[] pJunk;
	}

	MANUAL_MAPPING_DATA data{ 0 };
	
	if (Flags & INJ_FAKE_HEADER)
	{
		HINSTANCE hK32 = GetModuleHandle(TEXT("kernel32.dll"));

		if (!hK32)
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			return INJ_ERR_MODULE_MISSING;
		}

		data.hK32 = hK32;
	}

	if (Flags & (INJ_MM_RESOLVE_IMPORTS | INJ_MM_RUN_DLL_MAIN | INJ_MM_RESOLVE_DELAY_IMPORTS))
	{
		HINSTANCE hK32 = GetModuleHandle(TEXT("kernel32.dll"));

		if (!hK32)
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			return INJ_ERR_MODULE_MISSING;
		}
		
		data.pLoadLibraryA		= ReCa<f_LoadLibraryA>		(GetProcAddress(hK32, "LoadLibraryA"));
		data.pGetModuleHandleA	= ReCa<f_GetModuleHandleA>	(GetProcAddress(hK32, "GetModuleHandleA"));
		data.pGetProcAddress	= ReCa<f_GetProcAddress>	(GetProcAddress(hK32, "GetProcAddress"));
	}

	if (Flags & INJ_MM_ENABLE_SEH)
	{
		if (!NT::RtlInsertInvertedFunctionTable)
		{
			HINSTANCE hNTDLL = GetModuleHandle(TEXT("ntdll.dll"));

			if (!hNTDLL)
			{
				INIT_ERROR_DATA(error_data, GetLastError());

				return INJ_ERR_REMOTEMODULE_MISSING;
			}

			if (sym_ntdll_native_ret.wait_for(std::chrono::milliseconds(100)) != std::future_status::ready)
			{
				INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

				return INJ_ERR_SYMBOL_INIT_NOT_DONE;
			}

			DWORD sym_ret = sym_ntdll_native_ret.get();
			if (sym_ret != SYMBOL_ERR_SUCCESS)
			{
				INIT_ERROR_DATA(error_data, sym_ret);

				return INJ_ERR_SYMBOL_INIT_FAIL;
			}

			DWORD rva = 0;
			sym_ret = sym_ntdll_native.GetSymbolAddress("RtlInsertInvertedFunctionTable", rva);
			if (sym_ret != SYMBOL_ERR_SUCCESS || !rva)
			{
				INIT_ERROR_DATA(error_data, sym_ret);

				return INJ_ERR_SYMBOL_GET_FAIL;
			}

			NT::RtlInsertInvertedFunctionTable = ReCa<f_RtlInsertInvertedFunctionTable>(ReCa<BYTE*>(hNTDLL) + rva);
		}

		data.pRtlInsertInvertedFunctionTable = NT::RtlInsertInvertedFunctionTable;
	}

	if (Flags & INJ_MM_EXECUTE_TLS)
	{
		if (!NT::LdrpHandleTlsData)
		{
			HINSTANCE hNTDLL = GetModuleHandle(TEXT("ntdll.dll"));

			if (!hNTDLL)
			{
				INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

				return INJ_ERR_REMOTEMODULE_MISSING;
			}

			if (sym_ntdll_native_ret.wait_for(std::chrono::milliseconds(100)) != std::future_status::ready)
			{
				INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

				return INJ_ERR_SYMBOL_INIT_NOT_DONE;
			}

			DWORD sym_ret = sym_ntdll_native_ret.get();
			if (sym_ret != SYMBOL_ERR_SUCCESS)
			{
				INIT_ERROR_DATA(error_data, sym_ret);

				return INJ_ERR_SYMBOL_INIT_FAIL;
			}

			DWORD rva = 0;
			sym_ret = sym_ntdll_native.GetSymbolAddress("LdrpHandleTlsData", rva);
			if (sym_ret != SYMBOL_ERR_SUCCESS || !rva)
			{
				INIT_ERROR_DATA(error_data, sym_ret);

				return INJ_ERR_SYMBOL_GET_FAIL;
			}

			NT::LdrpHandleTlsData = ReCa<f_LdrpHandleTlsData>(ReCa<BYTE*>(hNTDLL) + rva);
		}

		data.pLdrpHandleTlsData = NT::LdrpHandleTlsData;
	}
	
	data.pModuleBase	= pTargetImageBase;
	data.Flags			= Flags;

	if (!WriteProcessMemory(hTargetProcess, pManualMappingData, &data, sizeof(data), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		return INJ_ERR_WPM_FAIL;
	}

	DWORD ShellcodeSize = ((UINT_PTR)ManualMapping_Shell_End - (UINT_PTR)ManualMapping_Shell) & 0xFFFFFFFF;

	if (!WriteProcessMemory(hTargetProcess, pShellcode, ManualMapping_Shell, ShellcodeSize, nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());
	
		return INJ_ERR_WPM_FAIL;
	}

	return INJ_ERR_SUCCESS;
}

DWORD MANUAL_MAPPER::RelocateImage(ERROR_DATA & error_data)
{
	BYTE * LocationDelta = pTargetImageBase - pLocalOptionalHeader->ImageBase;
	if (!LocationDelta)
	{
		return INJ_ERR_SUCCESS;
	}

	if (!pLocalOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return INJ_ERR_IMAGE_CANT_RELOC;
	}

	auto * pRelocData = ReCa<IMAGE_BASE_RELOCATION*>(pLocalImageBase + pLocalOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	while (pRelocData->VirtualAddress)
	{
		WORD * pRelativeInfo = ReCa<WORD*>(pRelocData + 1);
		UINT RelocCount = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		for (UINT i = 0; i < RelocCount; ++i, ++pRelativeInfo)
		{
			if (RELOC_FLAG(*pRelativeInfo))
			{
				ULONG_PTR * pPatch = ReCa<ULONG_PTR*>(pLocalImageBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
				*pPatch += ReCa<ULONG_PTR>(LocationDelta);
			}
		}

		pRelocData = ReCa<IMAGE_BASE_RELOCATION*>(ReCa<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
	}
	
	return INJ_ERR_SUCCESS;
}

DWORD MANUAL_MAPPER::InitSecurityCookie(ERROR_DATA & error_data)
{
	if (!(Flags & INJ_MM_INIT_SECURITY_COOKIE))
	{
		return INJ_ERR_SUCCESS;
	}

	if (!pLocalOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return INJ_ERR_LOAD_CONFIG_EMPTY;
	}

#ifdef _WIN64

	ULONGLONG new_cookie = GetTickCount64() & 0x0000FFFFFFFFFFFF;
	if (new_cookie == 0x2B992DDFA232)
	{
		++new_cookie;
	}
	else if (!(new_cookie & 0x0000FFFF00000000))
	{
		new_cookie |= (new_cookie | 0x4711) << 0x10;
	}

#else

	DWORD new_cookie = GetTickCount64() & 0xFFFFFFFF;
	if (new_cookie == 0xBB40E64E)
	{
		++new_cookie;
	}
	else if (!(new_cookie & 0xFFFF0000))
	{
		new_cookie |= (new_cookie | 0x4711) << 16;
	}

#endif
	
	auto pLoadConfigData = ReCa<IMAGE_LOAD_CONFIG_DIRECTORY*>(pLocalImageBase + pLocalOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
	pLoadConfigData->SecurityCookie = new_cookie;	

	return INJ_ERR_SUCCESS;
}

DWORD MANUAL_MAPPER::CopyImage(ERROR_DATA & error_data)
{
	if (!WriteProcessMemory(hTargetProcess, pTargetImageBase, pLocalImageBase, ImageSize, nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		return INJ_ERR_WPM_FAIL;
	}

	return INJ_ERR_SUCCESS;
}

DWORD MANUAL_MAPPER::SetPageProtections(ERROR_DATA & error_data)
{
	if (!(Flags & INJ_MM_SET_PAGE_PROTECTIONS))
	{
		return INJ_ERR_SUCCESS;
	}

	DWORD dwOld = NULL;
	if (!VirtualProtectEx(hTargetProcess, pTargetImageBase, pLocalOptionalHeader->SizeOfHeaders, PAGE_EXECUTE_READ, &dwOld))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		return INJ_ERR_CANT_SET_PAGE_PROT;
	}

	auto * pCurrentSectionHeader = IMAGE_FIRST_SECTION(pLocalNtHeaders);
	for (UINT i = 0; i != pLocalFileHeader->NumberOfSections; ++i, ++pCurrentSectionHeader)
	{
		void * pSectionBase		= pTargetImageBase + pCurrentSectionHeader->VirtualAddress;
		DWORD characteristics	= pCurrentSectionHeader->Characteristics;
		DWORD dwProt			= PAGE_NOACCESS;

		if (characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			if (characteristics & IMAGE_SCN_MEM_WRITE)
			{
				dwProt = PAGE_EXECUTE_READWRITE;
			}
			else if(characteristics & IMAGE_SCN_MEM_READ)
			{
				dwProt = PAGE_EXECUTE_READ;
			}
			else
			{
				dwProt = PAGE_EXECUTE;
			}
		}
		else
		{
			if (characteristics & IMAGE_SCN_MEM_WRITE)
			{
				dwProt = PAGE_READWRITE;
			}
			else if (characteristics & IMAGE_SCN_MEM_READ)
			{
				dwProt = PAGE_READONLY;
			}
		}
		
		if (!VirtualProtectEx(hTargetProcess, pSectionBase, pCurrentSectionHeader->Misc.VirtualSize, dwProt, &dwOld))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			return INJ_ERR_CANT_SET_PAGE_PROT;
		}
	}

	return INJ_ERR_SUCCESS;
}

DWORD _ManualMap(const wchar_t * szDllFile, HANDLE hTargetProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, ERROR_DATA & error_data)
{
	MANUAL_MAPPER Module{ 0 };
	BYTE * pRawData = nullptr;
		
	std::ifstream File(szDllFile, std::ios::binary | std::ios::ate);

	auto FileSize = File.tellg();

	pRawData = new BYTE[static_cast<size_t>(FileSize)];

	if (!pRawData)
	{
		File.close();

		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return INJ_ERR_OUT_OF_MEMORY_NEW;
	}

	File.seekg(0, std::ios::beg);
	File.read(ReCa<char*>(pRawData), FileSize);
	File.close();

	Module.hTargetProcess = hTargetProc;

	Module.pRawData			= pRawData;
	Module.pLocalDosHeader	= ReCa<IMAGE_DOS_HEADER*>(Module.pRawData);
	Module.pLocalNtHeaders	= ReCa<IMAGE_NT_HEADERS*>(Module.pRawData + Module.pLocalDosHeader->e_lfanew);
	Module.pLocalOptionalHeader = &Module.pLocalNtHeaders->OptionalHeader;
	Module.pLocalFileHeader		= &Module.pLocalNtHeaders->FileHeader;
	Module.ImageSize = Module.pLocalOptionalHeader->SizeOfImage;

	Module.Flags = Flags;
	
	DWORD dwRet = Module.AllocateMemory(error_data);
	if(dwRet != INJ_ERR_SUCCESS)
	{
		return dwRet;
	}

	dwRet = Module.CopyData(error_data);
	if(dwRet != INJ_ERR_SUCCESS)
	{
		return dwRet;
	}

	dwRet = Module.RelocateImage(error_data);
	if(dwRet != INJ_ERR_SUCCESS)
	{
		return dwRet;
	}
	
	dwRet = Module.CopyImage(error_data);
	if(dwRet != INJ_ERR_SUCCESS)
	{
		return dwRet;
	}

	DWORD remote_ret = 0;
	dwRet = StartRoutine(hTargetProc, ReCa<f_Routine>(Module.pShellcode), Module.pManualMappingData, Method, (Flags & INJ_THREAD_CREATE_CLOAKED) != 0, remote_ret, error_data);

	if (dwRet != SR_ERR_SUCCESS)
	{
		if (Method != LAUNCH_METHOD::LM_QueueUserAPC && !(Method == LAUNCH_METHOD::LM_HijackThread && dwRet == SR_HT_ERR_REMOTE_TIMEOUT))
		{
			Module.bKeepTarget = true;
		}

		return dwRet;
	}

	Module.bKeepTarget = true;

	dwRet = Module.SetPageProtections(error_data);
	if (dwRet != INJ_ERR_SUCCESS)
	{
		return dwRet;
	}

	auto zero_size = Module.AllocationSize - (Module.pManualMappingData - Module.pAllocationBase);
	BYTE * zero_bytes = new BYTE[zero_size];
	memset(zero_bytes, 0, zero_size);

	MANUAL_MAPPING_DATA data{ 0 };
	if (!ReadProcessMemory(hTargetProc, Module.pManualMappingData, &data, sizeof(data), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		WriteProcessMemory(hTargetProc, Module.pManualMappingData, zero_bytes, zero_size, nullptr);

		return INJ_ERR_VERIFY_RESULT_FAIL;
	}

	WriteProcessMemory(hTargetProc, Module.pManualMappingData, zero_bytes, zero_size, nullptr);

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

	return dwRet;
}

DWORD ManualMapping_Shell(MANUAL_MAPPING_DATA * pData)
{
	if (!pData)
	{
		return INJ_MM_ERR_NO_DATA;
	}

	BYTE * pBase	= pData->pModuleBase;
	auto * pOp		= &ReCa<IMAGE_NT_HEADERS*>(pBase + ReCa<IMAGE_DOS_HEADER*>(pBase)->e_lfanew)->OptionalHeader;
	DWORD _Flags	= pData->Flags;
	auto _DllMain	= ReCa<f_DLL_ENTRY_POINT>(pBase + pOp->AddressOfEntryPoint);

	if ((_Flags & (INJ_MM_RESOLVE_IMPORTS | INJ_MM_RUN_DLL_MAIN)) && pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		auto _LoadLibraryA		= pData->pLoadLibraryA;
		auto _GetModuleHandleA	= pData->pGetModuleHandleA;
		auto _GetProcAddress	= pData->pGetProcAddress;

		if (!_LoadLibraryA)
		{
			return INJ_MM_LOADLIBRARYA_MISSING;
		}
		else if (!_GetModuleHandleA)
		{
			return INJ_MM_GETMODULEHANDLEA_MISSING;
		}
		else if (!_GetProcAddress)
		{
			return INJ_MM_GETPROCADDRESS_MISSING;
		}

		auto * pImportDescr = ReCa<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name)
		{
			char * szMod = ReCa<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _GetModuleHandleA(szMod);
			if (!hDll)
			{
				hDll = _LoadLibraryA(szMod);
				if (!hDll)
				{
					return INJ_MM_CANT_LOAD_MODULE;
				}
			}

			IMAGE_THUNK_DATA * pThunk	= ReCa<IMAGE_THUNK_DATA*>(pBase + pImportDescr->OriginalFirstThunk);
			IMAGE_THUNK_DATA * pIAT		= ReCa<IMAGE_THUNK_DATA*>(pBase + pImportDescr->FirstThunk);

			if (!pImportDescr->OriginalFirstThunk)
			{
				pThunk = pIAT;
			}

			for (; pThunk->u1.AddressOfData; ++pThunk, ++pIAT)
			{
				ULONG_PTR * pFuncRef = ReCa<ULONG_PTR*>(pIAT);

				if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal))
				{
					*pFuncRef = _GetProcAddress(hDll, ReCa<char*>((pThunk->u1.Ordinal) & 0xFFFF));
				}
				else
				{
					auto * pImport = ReCa<IMAGE_IMPORT_BY_NAME*>(pBase + (pThunk->u1.AddressOfData));
					*pFuncRef = _GetProcAddress(hDll, pImport->Name);
				}

				if (!(*pFuncRef))
				{
					return INJ_MM_CANT_GET_IMPORT;
				}
			}

			++pImportDescr;
		}
	}

	if ((_Flags & INJ_MM_RESOLVE_DELAY_IMPORTS) && pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size)
	{
		auto _LoadLibraryA		= pData->pLoadLibraryA;
		auto _GetModuleHandleA	= pData->pGetModuleHandleA;
		auto _GetProcAddress	= pData->pGetProcAddress;

		if (!_LoadLibraryA)
		{
			return INJ_MM_LOADLIBRARYA_MISSING;
		}
		else if (!_GetModuleHandleA)
		{
			return INJ_MM_GETMODULEHANDLEA_MISSING;
		}
		else if (!_GetProcAddress)
		{
			return INJ_MM_GETPROCADDRESS_MISSING;
		}
	
		auto * pDelayImportDescr = ReCa<IMAGE_DELAYLOAD_DESCRIPTOR*>(pBase + pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);
		while (pDelayImportDescr->DllNameRVA)
		{
			char * szMod = ReCa<char*>(pBase + pDelayImportDescr->DllNameRVA);
			HINSTANCE hDll = _GetModuleHandleA(szMod);
			if (!hDll)
			{
				hDll = _LoadLibraryA(szMod);
				if (!hDll)
				{
					return INJ_MM_CANT_LOAD_DELAY_MODULE;
				}
			}

			if (pDelayImportDescr->ModuleHandleRVA)
			{
				HINSTANCE * pModule = ReCa<HINSTANCE*>(pBase + pDelayImportDescr->ModuleHandleRVA);
				*pModule = hDll;
			}
			
			IMAGE_THUNK_DATA * pIAT			= ReCa<IMAGE_THUNK_DATA*>(pBase + pDelayImportDescr->ImportAddressTableRVA);
			IMAGE_THUNK_DATA * pNameTable	= ReCa<IMAGE_THUNK_DATA*>(pBase + pDelayImportDescr->ImportNameTableRVA);

			for (; pIAT->u1.Function; ++pIAT, ++pNameTable)
			{
				ULONG_PTR * pFuncRef = ReCa<ULONG_PTR*>(pIAT->u1.Function);

				if (IMAGE_SNAP_BY_ORDINAL(pNameTable->u1.Ordinal))
				{
					*pFuncRef = _GetProcAddress(hDll, ReCa<char*>((pNameTable->u1.Ordinal) & 0xFFFF));
				}
				else
				{
					auto * pImport = ReCa<IMAGE_IMPORT_BY_NAME*>(pBase + (pNameTable->u1.AddressOfData));
					*pFuncRef = _GetProcAddress(hDll, pImport->Name);
				}

				if (!(*pFuncRef))
				{
					return INJ_MM_CANT_GET_DELAY_IMPORT;
				}
			}

			++pDelayImportDescr;
		}
	}

	if (_Flags & INJ_MM_ENABLE_SEH)
	{
		auto _RtlInsertInvertedFunctionTable = pData->pRtlInsertInvertedFunctionTable;
		if (!_RtlInsertInvertedFunctionTable)
		{
			return INJ_MM_FUNCTION_TABLE_MISSING;
		}
		else if (NT_FAIL(_RtlInsertInvertedFunctionTable(pBase, pOp->SizeOfImage)))
		{
			return INJ_MM_ENABLING_SEH_FAILED;
		}
	}

	if ((_Flags & INJ_MM_EXECUTE_TLS) && pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		auto * pTLS = ReCa<IMAGE_TLS_DIRECTORY*>(pBase + pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		
		if (pTLS->StartAddressOfRawData)
		{
			pData->pLdrpHandleTlsData(pBase);
		}

		auto * pCallback = ReCa<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && (*pCallback); ++pCallback)
		{
			auto Callback = *pCallback;
			Callback(pBase, DLL_PROCESS_ATTACH, nullptr);
		}
	}

	if (_Flags & INJ_MM_RUN_DLL_MAIN)
	{
		_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);
	}
	
	if (_Flags & INJ_MM_CLEAN_DATA_DIR)
	{	
		DWORD Size = pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
		if (Size)
		{
			auto * pImportDescr = ReCa<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
			while (pImportDescr->Name)
			{
				char * szMod = ReCa<char*>(pBase + pImportDescr->Name);
				for (; *szMod++; *szMod = '\0');
				pImportDescr->Name = 0;

				IMAGE_THUNK_DATA * pThunk	= ReCa<IMAGE_THUNK_DATA *>(pBase + pImportDescr->OriginalFirstThunk);
				IMAGE_THUNK_DATA * pIAT		= ReCa<IMAGE_THUNK_DATA *>(pBase + pImportDescr->FirstThunk);

				if (!pImportDescr->OriginalFirstThunk)
				{
					pThunk = pIAT;
				}

				for (; pThunk->u1.AddressOfData; ++pThunk, ++pIAT)
				{
					if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal))
					{
						pThunk->u1.Ordinal = 0;
					}
					else
					{
						auto * pImport = ReCa<IMAGE_IMPORT_BY_NAME *>(pBase + (pThunk->u1.AddressOfData));
						char * szFunc = pImport->Name;
						for (; *szFunc++; *szFunc = '\0');
					}
				}

				pImportDescr->OriginalFirstThunk	= 0;
				pImportDescr->FirstThunk			= 0;

				++pImportDescr;
			}

			pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
			pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size			= 0;
		}

		Size = pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size;
		if (Size)
		{
			auto * pDelayImportDescr = ReCa<IMAGE_DELAYLOAD_DESCRIPTOR*>(pBase + pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);

			while (pDelayImportDescr->DllNameRVA)
			{
				char * szMod = ReCa<char*>(pBase + pDelayImportDescr->DllNameRVA);
				for (; *szMod++; *szMod = '\0');
				pDelayImportDescr->DllNameRVA = 0;

				pDelayImportDescr->ModuleHandleRVA = 0;
				
				IMAGE_THUNK_DATA * pIAT			= ReCa<IMAGE_THUNK_DATA*>(pBase + pDelayImportDescr->ImportAddressTableRVA);
				IMAGE_THUNK_DATA * pNameTable	= ReCa<IMAGE_THUNK_DATA*>(pBase + pDelayImportDescr->ImportNameTableRVA);

				for (; pIAT->u1.Function; ++pIAT, ++pNameTable)
				{

					if (IMAGE_SNAP_BY_ORDINAL(pNameTable->u1.Ordinal))
					{
						pNameTable->u1.Ordinal = 0;
					}
					else
					{
						auto * pImport = ReCa<IMAGE_IMPORT_BY_NAME *>(pBase + (pNameTable->u1.AddressOfData));
						char * szFunc = pImport->Name;
						for (; *szFunc++; *szFunc = '\0');
					}
				}

				pDelayImportDescr->ImportAddressTableRVA	= 0;
				pDelayImportDescr->ImportNameTableRVA		= 0;

				++pDelayImportDescr;
			}

			pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress	= 0;
			pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size				= 0;
		}

		Size = pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
		if (Size)
		{
			auto * pDebugDir = ReCa<IMAGE_DEBUG_DIRECTORY*>(pBase + pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);

			BYTE * pDebugData = pBase + pDebugDir->AddressOfRawData;
			for (UINT i = 0; i != pDebugDir->SizeOfData; ++i, ++pDebugData)
			{
				*pDebugData = 0;
			}

			pDebugDir->SizeOfData		= 0;
			pDebugDir->AddressOfRawData = 0;
			pDebugDir->PointerToRawData = 0;

			pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress	= 0;
			pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size			= 0;
		}

		Size = pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
		if (Size)
		{
			auto * pRelocData = ReCa<IMAGE_BASE_RELOCATION*>(pBase + pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			while (pRelocData->VirtualAddress)
			{
				WORD * pRelativeInfo = ReCa<WORD*>(pRelocData + 1);
				UINT RelocCount = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

				for (UINT i = 0; i < RelocCount; ++i, ++pRelativeInfo)
				{
					*pRelativeInfo = 0;
				}

				pRelocData = ReCa<IMAGE_BASE_RELOCATION*>(ReCa<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}

			pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress	= 0;
			pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size			= 0;
		}

		Size = pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
		if (Size)
		{
			auto * pTLS = ReCa<IMAGE_TLS_DIRECTORY*>(pBase + pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
			auto * pCallback = ReCa<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
			for (; pCallback && (*pCallback); ++pCallback)
			{
				*pCallback = nullptr;
			}

			pTLS->AddressOfCallBacks	= 0;
			pTLS->AddressOfIndex		= 0;
			pTLS->EndAddressOfRawData	= 0;
			pTLS->SizeOfZeroFill		= 0;
			pTLS->StartAddressOfRawData = 0;

			pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress	= 0;
			pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size				= 0;
		}
	}

	if (_Flags & INJ_ERASE_HEADER)
	{
		for (UINT i = 0; i != 0x1000 / sizeof(UINT64); ++i)
		{
			*(ReCa<UINT64*>(pBase) + i) = 0;
		}
	}
	else if (_Flags & INJ_FAKE_HEADER)
	{
		if (!pData->hK32)
		{
			return INJ_MM_KERNEL32_POINTER_MISSING;
		}

		UINT64 * k32_data = ReCa<UINT64*>(pData->hK32);

		for (UINT i = 0; i != 0x1000 / sizeof(UINT64); ++i)
		{
			*(ReCa<UINT64*>(pBase) + i) = k32_data[i];
		}
	}

	pData->hRet = ReCa<HINSTANCE>(pBase);

	return INJ_ERR_SUCCESS;
}

DWORD ManualMapping_Shell_End() { return 3; }