#pragma once

#ifdef _WIN64

#include "pch.h"

#define FUNC_WOW64(Function) inline DWORD Function##_WOW64 = 0

namespace REMOTE
{
	FUNC_WOW64(LoadLibraryExW);
	FUNC_WOW64(LdrLoadDll);
	FUNC_WOW64(LdrpLoadDll);
	FUNC_WOW64(LdrpHandleTlsData);
	FUNC_WOW64(LoadLibraryA);
	FUNC_WOW64(GetModuleHandleA);
	FUNC_WOW64(GetProcAddress);
	FUNC_WOW64(RtlInsertInvertedFunctionTable);
};

#endif