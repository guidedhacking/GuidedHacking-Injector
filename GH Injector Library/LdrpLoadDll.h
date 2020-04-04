#pragma once

#include "Injection.h"

struct LDRP_LOAD_DLL_DATA
{
	HINSTANCE		hRet;
	f_LdrpLoadDll	pLdrpLoadDll;
	NTSTATUS		ntRet;
	UNICODE_STRING	pModuleFileName;
	BYTE			Data[MAXPATH_IN_BYTE_W];

	LDRP_PATH_SEARCH_CONTEXT		search_path_buffer;
	LDR_DATA_TABLE_ENTRY		*	p_entry_out;
};

#ifdef _WIN64

struct LDRP_LOAD_DLL_DATA_WOW64
{
	DWORD				hRet;
	DWORD				pLdrpLoadDll;
	NTSTATUS			ntRet;
	UNICODE_STRING32	pModuleFileName;
	BYTE				Data[MAXPATH_IN_BYTE_W];
	UINT_PTR			search_path_data[4];

	LDRP_PATH_SEARCH_CONTEXT32	search_path_buffer;
	DWORD						p_entry_out;
};

#endif