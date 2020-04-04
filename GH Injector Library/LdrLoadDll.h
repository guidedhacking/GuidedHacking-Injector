#pragma once

#include "Injection.h"

struct LDR_LOAD_DLL_DATA
{
	HINSTANCE		hRet;
	f_LdrLoadDll	pLdrLoadDll;
	NTSTATUS		ntRet;
	UNICODE_STRING	pModuleFileName;
	BYTE			Data[MAXPATH_IN_BYTE_W];
};

#ifdef _WIN64

struct LDR_LOAD_DLL_DATA_WOW64
{
	DWORD				hRet;
	DWORD				pLdrLoadDll;
	NTSTATUS			ntRet;
	UNICODE_STRING32	pModuleFileName;
	BYTE				Data[MAXPATH_IN_BYTE_W];
};

#endif