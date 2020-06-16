#include "pch.h"

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "Urlmon.lib")

#if (PSAPI_VERSION == 1)
#pragma comment(lib, "Psapi.lib")
#endif