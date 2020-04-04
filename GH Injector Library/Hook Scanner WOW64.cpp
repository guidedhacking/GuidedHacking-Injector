#include "pch.h"

#ifdef _WIN64

#include "Hook Scanner.h"

bool ScanForHook_WOW64(HookInfo & Info, HANDLE hTargetProc)
{
	if(!GetProcAddressEx_WOW64((HANDLE)Info.pReference, Info.hModuleBase, Info.FunctionName.c_str(), Info.pFunc))
	{
		Info.ErrorCode = HOOK_SCAN_ERR_GETPROCADDRESS_FAILED;;

		return false;
	}

	if (!ReadProcessMemory((HANDLE)Info.pReference, Info.pFunc, Info.OriginalBytes, sizeof(Info.OriginalBytes), nullptr))
	{
		Info.ErrorCode = HOOK_SCAN_ERR_READ_PROCESS_MEMORY_FAILED;

		return false;
	}

	BYTE Buffer[HOOK_SCAN_BYTE_COUNT]{ 0 };
	if (!ReadProcessMemory(hTargetProc, Info.pFunc, Buffer, sizeof(Buffer), nullptr))
	{
		Info.ErrorCode = HOOK_SCAN_ERR_READ_PROCESS_MEMORY_FAILED;

		return false;
	}


	for (int i = 0; i != HOOK_SCAN_BYTE_COUNT; ++i)
	{
		if (Info.OriginalBytes[i] != Buffer[i])
		{
			++Info.ChangeCount;
		}
	}

	return (Info.ChangeCount != 0);
}

#endif