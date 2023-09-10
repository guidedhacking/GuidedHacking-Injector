/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

#pragma once

#include "VEH Shell.h"

#define RELOC_FLAG86(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG86
#endif

#define HKDATASIG_64 0x1234123412341234
#define HKDATASIG_32 0x12341234

#ifdef _WIN64
#define HKDATASIG HKDATASIG_64
#else
#define HKDATASIG HKDATASIG_32
#endif

#define DLL_NAME_BUFFER_SIZE 0x20
#define HOOKED_FUNCS_NAME_BUFFER_SIZE 0x20

struct VEH_SHELL_DATA;

namespace MMAP_NATIVE
{
	struct MANUAL_MAPPING_DATA;
	struct MANUAL_MAPPING_FUNCTION_TABLE;
}

using f_DLL_ENTRY_POINT = BOOL(WINAPI *)(HINSTANCE hDll, DWORD dwReason, void * pReserved);
using f_MMI_FUNCTION = DWORD(__stdcall *)(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);

//list to track imports and unload on failure
typedef struct _MM_DEPENDENCY_RECORD
{
	struct _MM_DEPENDENCY_RECORD * Next = nullptr;
	struct _MM_DEPENDENCY_RECORD * Prev = nullptr;

	HANDLE DllHandle = nullptr;
	UNICODE_STRING DllName{ 0 };
	wchar_t Buffer[0x100] { 0 };
	
} MM_DEPENDENCY_RECORD, * PMM_DEPENDENCY_RECORD;

DWORD __declspec(code_seg(".mmap_sec$01")) __stdcall ManualMapping_Shell		(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".mmap_sec$02")) __stdcall MMI_MapSections			(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".mmap_sec$03")) __stdcall MMI_RelocateImage			(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".mmap_sec$04")) __stdcall MMI_InitializeCookie		(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".mmap_sec$06")) __stdcall MMI_LoadImports			(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".mmap_sec$07")) __stdcall MMI_LoadDelayImports		(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".mmap_sec$08")) __stdcall MMI_SetPageProtections		(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".mmap_sec$09")) __stdcall MMI_EnableExceptions		(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".mmap_sec$0A")) __stdcall MMI_HandleTLS				(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".mmap_sec$0B")) __stdcall MMI_ExecuteDllMain			(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".mmap_sec$0C")) __stdcall MMI_CleanDataDirectories	(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".mmap_sec$0D")) __stdcall MMI_CloakHeader			(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".mmap_sec$0E")) __stdcall MMI_CleanUp				(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);

NTSTATUS __declspec(code_seg(".mmap_sec$11")) __stdcall MMIH_ResolveFilePath(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData, UNICODE_STRING * Module);
NTSTATUS __declspec(code_seg(".mmap_sec$12")) __stdcall MMIH_PreprocessModuleName(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData, const char * szModule, UNICODE_STRING * ModuleName, LDRP_LOAD_CONTEXT_FLAGS * CtxFlags);
NTSTATUS __declspec(code_seg(".mmap_sec$13")) __stdcall MMIH_LoadModule(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData, UNICODE_STRING * Module, LDRP_LOAD_CONTEXT_FLAGS CtxFlag, HINSTANCE * hModule, MM_DEPENDENCY_RECORD ** head);

DWORD __declspec(code_seg(".mmap_sec$14")) MMAP_SEC_END();

namespace MMAP_NATIVE
{
	using namespace NATIVE;

	ALIGN struct MANUAL_MAPPING_FUNCTION_TABLE
	{
		ALIGN NT_FUNC_LOCAL(NtOpenFile);
		ALIGN NT_FUNC_LOCAL(NtReadFile);
		ALIGN NT_FUNC_LOCAL(NtClose);

		ALIGN NT_FUNC_LOCAL(NtSetInformationFile);
		ALIGN NT_FUNC_LOCAL(NtQueryInformationFile);

		ALIGN NT_FUNC_LOCAL(NtAllocateVirtualMemory);
		ALIGN NT_FUNC_LOCAL(NtProtectVirtualMemory);
		ALIGN NT_FUNC_LOCAL(NtFreeVirtualMemory);

		ALIGN NT_FUNC_LOCAL(NtCreateSection);
		ALIGN NT_FUNC_LOCAL(NtMapViewOfSection);

		ALIGN NT_FUNC_LOCAL(memmove);
		ALIGN NT_FUNC_LOCAL(RtlZeroMemory);
		ALIGN NT_FUNC_LOCAL(RtlAllocateHeap);
		ALIGN NT_FUNC_LOCAL(RtlFreeHeap);

		ALIGN NT_FUNC_LOCAL(LdrpLoadDll);
		ALIGN NT_FUNC_LOCAL(LdrpLoadDllInternal);
		ALIGN NT_FUNC_LOCAL(LdrGetProcedureAddress);

		ALIGN NT_FUNC_LOCAL(LdrUnloadDll);

		ALIGN NT_FUNC_LOCAL(RtlAnsiStringToUnicodeString);
		ALIGN NT_FUNC_LOCAL(RtlUnicodeStringToAnsiString);
		ALIGN NT_FUNC_LOCAL(RtlCompareUnicodeString);
		ALIGN NT_FUNC_LOCAL(RtlCompareString);

		ALIGN NT_FUNC_LOCAL(LdrGetDllPath);
		ALIGN NT_FUNC_LOCAL(LdrpPreprocessDllName);
		ALIGN NT_FUNC_LOCAL(RtlInsertInvertedFunctionTable);
#ifdef _WIN64
		ALIGN NT_FUNC_LOCAL(RtlAddFunctionTable);
#endif
		ALIGN NT_FUNC_LOCAL(LdrpHandleTlsData);

		ALIGN NT_FUNC_LOCAL(LdrLockLoaderLock);
		ALIGN NT_FUNC_LOCAL(LdrUnlockLoaderLock);

		ALIGN NT_FUNC_LOCAL(LdrpDereferenceModule);

		ALIGN NT_FUNC_LOCAL(LdrProtectMrdata);

		ALIGN NT_FUNC_LOCAL(RtlAddVectoredExceptionHandler);
		ALIGN NT_FUNC_LOCAL(RtlRemoveVectoredExceptionHandler);

		ALIGN NT_FUNC_LOCAL(LdrpModuleBaseAddressIndex);
		ALIGN NT_FUNC_LOCAL(LdrpMappingInfoIndex);
		ALIGN NT_FUNC_LOCAL(LdrpHeap);
		ALIGN NT_FUNC_LOCAL(LdrpInvertedFunctionTable);
		ALIGN NT_FUNC_LOCAL(LdrpDefaultPath);
		ALIGN NT_FUNC_LOCAL(LdrpTlsList);

		ALIGN f_MMI_FUNCTION MMP_Shell					= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_MapSections			= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_RelocateImage			= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_InitializeCookie		= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_LoadImports			= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_LoadDelayImports		= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_SetPageProtections	= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_EnableExceptions		= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_HandleTLS				= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_ExecuteDllMain		= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_CleanDataDirectories	= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_CloakHeader			= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_CleanUp				= nullptr;

		ALIGN decltype(MMIH_ResolveFilePath)			* MMIHP_ResolveFilePath				= nullptr;
		ALIGN decltype(MMIH_PreprocessModuleName)		* MMIHP_PreprocessModuleName		= nullptr;
		ALIGN decltype(MMIH_LoadModule)					* MMIHP_LoadModule					= nullptr;

		ALIGN void * pLdrpHeap = nullptr;

		MANUAL_MAPPING_FUNCTION_TABLE();
	};

	ALIGN struct MANUAL_MAPPING_DATA
	{
		ALIGN HINSTANCE	hRet		= NULL;
		ALIGN DWORD		Flags		= NULL;
		ALIGN NTSTATUS	ntRet		= STATUS_SUCCESS;

		ALIGN WORD ShiftOffset = 0;

		ALIGN UNICODE_STRING DllPath{ 0 };
		ALIGN wchar_t szPathBuffer[MAX_PATH]{ 0 };

		ALIGN wchar_t NtPathPrefix[8] = L"\\??\\\0\0\0";

		ALIGN DWORD OSVersion		= 0;
		ALIGN DWORD OSBuildNumber	= 0;

		ALIGN BYTE				*	pVEHShell			= nullptr;
		ALIGN DWORD					VEHShellSize		= 0;

		ALIGN HANDLE				hVEH				= nullptr;
		ALIGN BYTE				*	pVEHShellMapped		= nullptr;
		ALIGN VEH_SHELL_DATA	*	pVEHShellData		= nullptr;
		ALIGN void				*	pFakeSEHDirectory	= nullptr;

		ALIGN BYTE *	pAllocationBase	= nullptr;
		ALIGN BYTE *	pImageBase		= nullptr;
		ALIGN BYTE *	pRawData		= nullptr;
		ALIGN DWORD		RawSize			= 0;
		ALIGN HANDLE	hDllFile		= nullptr;
		
		ALIGN IMAGE_DOS_HEADER		* pDosHeader		= nullptr;
		ALIGN IMAGE_NT_HEADERS		* pNtHeaders		= nullptr;
		ALIGN IMAGE_OPTIONAL_HEADER	* pOptionalHeader	= nullptr;
		ALIGN IMAGE_FILE_HEADER		* pFileHeader		= nullptr;

		ALIGN MM_DEPENDENCY_RECORD * pImportsHead		= nullptr;
		ALIGN MM_DEPENDENCY_RECORD * pDelayImportsHead	= nullptr;

		ALIGN MANUAL_MAPPING_FUNCTION_TABLE * FunctionTable = nullptr;
	};
}

#ifdef _WIN64

namespace MMAP_WOW64
{
	using namespace WOW64;

	ALIGN_86 struct MANUAL_MAPPING_FUNCTION_TABLE_WOW64
	{
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(NtOpenFile);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(NtReadFile);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(NtClose);

		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(NtSetInformationFile);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(NtQueryInformationFile);

		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(NtAllocateVirtualMemory);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(NtProtectVirtualMemory);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(NtFreeVirtualMemory);

		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(NtCreateSection);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(NtMapViewOfSection);

		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(memmove);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(RtlZeroMemory);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(RtlAllocateHeap);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(RtlFreeHeap);

		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(LdrpLoadDll);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(LdrpLoadDllInternal);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(LdrGetProcedureAddress);

		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(LdrUnloadDll);

		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(RtlAnsiStringToUnicodeString);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(RtlUnicodeStringToAnsiString);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(RtlCompareUnicodeString);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(RtlCompareString);

		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(LdrGetDllPath);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(LdrpPreprocessDllName);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(RtlInsertInvertedFunctionTable);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(LdrpHandleTlsData);

		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(LdrLockLoaderLock);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(LdrUnlockLoaderLock);

		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(LdrpDereferenceModule);

		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(LdrProtectMrdata);

		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(RtlAddVectoredExceptionHandler);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(RtlRemoveVectoredExceptionHandler);

		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(LdrpModuleBaseAddressIndex);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(LdrpMappingInfoIndex);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(LdrpHeap);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(LdrpInvertedFunctionTable);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(LdrpDefaultPath);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(LdrpTlsList);

		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(MMP_Shell);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(MMIP_MapSections);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(MMIP_RelocateImage);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(MMIP_InitializeCookie);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(MMIP_LoadImports);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(MMIP_LoadDelayImports);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(MMIP_SetPageProtections);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(MMIP_EnableExceptions);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(MMIP_HandleTLS);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(MMIP_ExecuteDllMain);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(MMIP_CleanDataDirectories);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(MMIP_CloakHeader);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(MMIP_CleanUp);

		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(MMIHP_ResolveFilePath);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(MMIHP_PreprocessModuleName);
		ALIGN_86 WOW64_FUNCTION_POINTER_LOCAL(MMIHP_LoadModule);

		ALIGN_86 DWORD pLdrpHeap = 0;

		MANUAL_MAPPING_FUNCTION_TABLE_WOW64();
	};
	
	ALIGN_86 struct MANUAL_MAPPING_DATA_WOW64
	{
		ALIGN_86 DWORD	hRet	= NULL;
		ALIGN_86 DWORD	Flags	= NULL;
		ALIGN_86 DWORD	ntRet	= STATUS_SUCCESS;

		ALIGN_86 WORD ShiftOffset = 0;

		ALIGN_86 UNICODE_STRING_32 DllPath{ 0 };
		ALIGN_86 wchar_t szPathBuffer[MAX_PATH]{ 0 };

		ALIGN_86 wchar_t NtPathPrefix[8] = L"\\??\\\0\0\0";

		ALIGN_86 DWORD OSVersion		= 0;
		ALIGN_86 DWORD OSBuildNumber	= 0;

		ALIGN_86 DWORD pVEHShell	= 0;
		ALIGN_86 DWORD VEHShellSize = 0;

		ALIGN_86 DWORD hVEH					= 0;
		ALIGN_86 DWORD pVEHShellMapped		= 0;
		ALIGN_86 DWORD pVEHShellData		= 0;
		ALIGN_86 DWORD pFakeSEHDirectory	= 0;

		ALIGN_86 DWORD pAllocationBase	= 0;
		ALIGN_86 DWORD pImageBase		= 0;
		ALIGN_86 DWORD pRawData			= 0;
		ALIGN_86 DWORD RawSize			= 0;
		ALIGN_86 DWORD hDllFile			= 0;
		
		ALIGN_86 DWORD pDosHeader		= 0;
		ALIGN_86 DWORD pNtHeaders		= 0;
		ALIGN_86 DWORD pOptionalHeader	= 0;
		ALIGN_86 DWORD pFileHeader		= 0;

		ALIGN_86 DWORD pImportsHead			= 0;
		ALIGN_86 DWORD pDelayImportsHead	= 0;

		ALIGN_86 DWORD FunctionTable = 0;
	};
}

#endif

#pragma region inlined helper functions

__forceinline UINT_PTR bit_rotate_r(UINT_PTR val, int count)
{
	return (val >> count) | (val << (-count));
}

template <class T>
__forceinline T * NewObject(MMAP_NATIVE::MANUAL_MAPPING_FUNCTION_TABLE * f, size_t Count = 1)
{
	return ReCa<T *>(f->RtlAllocateHeap(f->pLdrpHeap, HEAP_ZERO_MEMORY, sizeof(T) * Count));
}

template <class T>
__forceinline void DeleteObject(MMAP_NATIVE::MANUAL_MAPPING_FUNCTION_TABLE * f, T * Object)
{
	if (Object)
	{
		f->RtlFreeHeap(f->pLdrpHeap, NULL, Object);
	}
}

__forceinline WORD SizeAnsiString(const char * szString)
{
	const char * c = szString;
	while (*c)
	{
		c++;
	}

	return (WORD)((c - szString) * sizeof(char));
}

__forceinline WORD SizeUnicodeString(const wchar_t * szString)
{
	const wchar_t * c = szString;
	while (*c)
	{
		c++;
	}

	return (WORD)((c - szString) * sizeof(wchar_t));
}

__forceinline bool InitAnsiString(MMAP_NATIVE::MANUAL_MAPPING_FUNCTION_TABLE * f, ANSI_STRING * String, const char * szString)
{
	const char * c = szString;
	while (*c)
	{
		c++;
	}

	WORD Length = (WORD)(c - szString);
	if (!Length)
	{
		return false;
	}

	String->szBuffer = NewObject<char>(f, (((size_t)Length) + 1) / sizeof(char));
	if (!String->szBuffer)
	{
		return false;
	}

	String->Length = Length;
	String->MaxLength = Length + 1 * sizeof(char);
	f->memmove(String->szBuffer, szString, Length);

	return true;
}

#pragma endregion