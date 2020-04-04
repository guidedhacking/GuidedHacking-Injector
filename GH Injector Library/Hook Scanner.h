#pragma once

#include "pch.h"

#include "Error.h"
#include "Tools.h"
#include "Import Handler.h"

#define HOOK_SCAN_BYTE_COUNT 0x10

struct HookInfo
{
	std::string	ModulePath;
	std::string FunctionName;

	HINSTANCE		hModuleBase;
	BYTE		*	pReference;
	void		*	pFunc;
	UINT			ChangeCount;
	BYTE			OriginalBytes[HOOK_SCAN_BYTE_COUNT];

	DWORD ErrorCode;
};

bool __stdcall ValidateInjectionFunctions(DWORD dwTargetProcessId, DWORD & ErrorCode, DWORD & LastWin32Error, std::vector<HookInfo> & HookDataOut);
bool __stdcall RestoreInjectionFunctions(DWORD dwTargetProcessId, DWORD & ErrorCode, DWORD & LastWin32Error, std::vector<HookInfo> & HookDataIn);

bool ScanForHook(HookInfo & Info, HANDLE hTargetProcess);

#ifdef _WIN64
bool ScanForHook_WOW64(HookInfo & Info, HANDLE hTargetProc);
#endif