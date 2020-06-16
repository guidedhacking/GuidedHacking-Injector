#pragma once

#include "Tools.h"

#define HOOK_SCAN_BYTE_COUNT 0x10

struct HookInfo
{
	const char * ModuleName;
	const char * FunctionName;

	HINSTANCE		hModuleBase;
	void		*	pFunc;
	UINT			ChangeCount;
	BYTE			OriginalBytes[HOOK_SCAN_BYTE_COUNT];

	DWORD ErrorCode;
};

bool __stdcall ValidateInjectionFunctions(DWORD dwTargetProcessId, DWORD & ErrorCode, DWORD & LastWin32Error, HookInfo * HookDataOut, UINT Count, UINT * CountOut);
bool __stdcall RestoreInjectionFunctions(DWORD dwTargetProcessId, DWORD & ErrorCode, DWORD & LastWin32Error, HookInfo * HookDataIn, UINT Count, UINT * CountOut);

bool ScanForHook(HookInfo & Info, HANDLE hTargetProcess);

#ifdef _WIN64
bool ScanForHook_WOW64(HookInfo & Info, HANDLE hTargetProc, HANDLE hRefProc);
#endif