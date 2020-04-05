#pragma once

//winapi shit
#include <Windows.h>

//enum shit
#include <TlHelp32.h>
#include <Psapi.h>

//string shit
#include <strsafe.h>
#include <tchar.h>

//file shit
#include <fstream>

//dank shit
#include <vector>
#include <ctime>
#include <map>

//session shit
#include <wtsapi32.h>

//symbol shit
#include <DbgHelp.h>
#include <urlmon.h>
#include <future>

//warning shit
#pragma warning(disable: 4201) //unnamed union
#pragma warning(disable: 4324) //structure member alignment resulting in additional bytes being added as padding
#pragma warning(disable: 6001) //uninitialized memory & handles (false positive in for loops with continue statements)
#pragma warning(disable: 6258) //TerminateThread warning
#pragma warning(disable: 6387) //pointer could be 0 (false positive "Manual Mapping WOW64.cpp")

#ifdef _DEBUG
#include <iostream>
#endif

//reinterpret_cast = too long to type
#define ReCa reinterpret_cast

//Macro used to export the functions with a proper name.
#define EXPORT_FUNCTION(export_name, link_name) comment(linker, "/EXPORT:" export_name "=" link_name)

//converts the __FILEW__ macro to filename only (thanks stackoverflow)
#define __FILENAMEW__ (wcsrchr(__FILEW__, '\\') + 1)

#define SM_EXE_FILENAME64 L"GH Injector SM - x64.exe"
#define SM_EXE_FILENAME86 L"GH Injector SM - x86.exe"

#define SM_INFO_FILENAME64 L"SM64.txt"
#define SM_INFO_FILENAME86 L"SM86.txt"

#ifdef _WIN64
#define SM_INFO_FILENAME SM_INFO_FILENAME64
#define SM_EXE_FILENAME SM_EXE_FILENAME64
#else
#define SM_INFO_FILENAME SM_INFO_FILENAME86
#define SM_EXE_FILENAME SM_EXE_FILENAME86
#endif

enum class INJECTION_MODE
{
	IM_LoadLibraryExW,
	IM_LdrLoadDll,
	IM_LdrpLoadDll,
	IM_ManualMap
};
//Enum to define the injection mode.

enum class LAUNCH_METHOD
{
	LM_NtCreateThreadEx,
	LM_HijackThread,
	LM_SetWindowsHookEx,
	LM_QueueUserAPC
};
//enum which is used to select the method to execute the shellcode