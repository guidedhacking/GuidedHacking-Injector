#pragma once

#include "Injection.h"

using f_LoadLibraryExW = decltype(LoadLibraryExW);

struct LOAD_LIBRARY_EXW_DATA
{
	HINSTANCE			hRet;
	f_LoadLibraryExW *  pLoadLibraryExW;
	wchar_t				szDll[MAXPATH_IN_TCHAR];
};

#ifdef _WIN64

struct LOAD_LIBRARY_EXW_DATA_WOW64
{
	DWORD	hRet;
	DWORD	pLoadLibraryExW;
	wchar_t	szDll[MAXPATH_IN_TCHAR];
};

#endif