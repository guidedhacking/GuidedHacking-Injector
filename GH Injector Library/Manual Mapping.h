#pragma once

#include "Manual Mapping Internal.h"

#define MIN_SHIFT_OFFSET	0x100
#define MAX_SHIFT_OFFSET	0x1000

namespace MMAP_NATIVE
{
	DWORD ManualMap(const INJECTION_SOURCE & DllPath, HANDLE hTargetProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD Timeout, ERROR_DATA & error_data);
}

#ifdef _WIN64

namespace MMAP_WOW64
{
	DWORD ManualMap_WOW64(const INJECTION_SOURCE & DllPath, HANDLE hTargetProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD Timeout, ERROR_DATA & error_data);
}

#endif