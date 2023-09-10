/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

#pragma once

//winapi shit
#include <Windows.h>

#if (NTDDI_VERSION < NTDDI_WIN7)
#error The mininum requirement for this library is Windows 7.
#endif

//enum shit
#include <TlHelp32.h>
#include <Psapi.h>

//string shit
#include <format>
#include <sstream>
#include <string>
#include <tchar.h>

//file shit
#include <fstream>
#include <shlwapi.h>

//dank shit
#include <ctime>
#include <map>
#include <random>
#include <vector>

//session shit
#include <wtsapi32.h>

//symbol shit
#include <DbgHelp.h>
#include <future>

//internet shit
#include <WinInet.h>
#include <Urlmon.h>

//warning shit
#pragma warning(disable: 4201) //unnamed union (nt structures)
#pragma warning(disable: 4324) //structure member alignment resulting in additional bytes being added as padding
#pragma warning(disable: 6001) //uninitialized memory & handles (false positive in for loops with continue statements)
#pragma warning(disable: 6258) //TerminateThread warning
#pragma warning(disable: 28159) //I want to use GetTickCount, suck it Bill

//reinterpret_cast = too long to type
#define ReCa reinterpret_cast

//Macro to convert 32-bit DWORD into void*
#define MPTR(d) (void *)(ULONG_PTR)d

//Macro to convert dumb 64-types into a DWORD without triggereing C4302 or C4311 (also works on 32-bit sized pointers)
#define MDWD(p) (DWORD)((ULONG_PTR)p & 0xFFFFFFFF)

//Macro used to export the functions with a proper name
#define EXPORT_FUNCTION(export_name, link_name) comment(linker, "/EXPORT:" export_name "=" link_name)

//converts the __FILEW__ macro to filename only (thanks stackoverflow)
#define __FILENAMEW__ (wcsrchr(__FILEW__, '\\') + 1)

#define SM_EXE_FILENAME64 L"GH Injector SM - x64.exe"
#define SM_EXE_FILENAME86 L"GH Injector SM - x86.exe"

#define SM_INFO_FILENAME64 L"SM64.txt"
#define SM_INFO_FILENAME86 L"SM86.txt"

#define DNP_DLL_FILENAME64 L"GH Injector DNP - x64.dll"
#define DNP_DLL_FILENAME86 L"GH Injector DNP - x86.dll"

#define DNP_INFO_FILENAME L"DNPD.txt"

#ifdef _WIN64
#define SM_INFO_FILENAME SM_INFO_FILENAME64
#define SM_EXE_FILENAME SM_EXE_FILENAME64
#define DNP_DLL_FILENAME DNP_DLL_FILENAME64
#else
#define SM_INFO_FILENAME SM_INFO_FILENAME86
#define SM_EXE_FILENAME SM_EXE_FILENAME86
#define DNP_DLL_FILENAME DNP_DLL_FILENAME86
#endif

//Enum to define the injection mode.
enum class INJECTION_MODE
{
	IM_LoadLibraryExW,
	IM_LdrLoadDll,
	IM_LdrpLoadDll,
	IM_LdrpLoadDllInternal,
	IM_ManualMap
};

//enum which is used to select the method to execute the shellcode
enum class LAUNCH_METHOD
{
	LM_NtCreateThreadEx,
	LM_HijackThread,
	LM_SetWindowsHookEx,
	LM_QueueUserAPC,
	LM_KernelCallback,
	LM_FakeVEH
};

//macro to avoid compiler and shellcode related alignment issues (unlikely but just to be sure)
#define ALIGN_64 __declspec(align(8))
#define ALIGN_86 __declspec(align(4))

#ifdef _WIN64
#define ALIGN ALIGN_64
#else
#define ALIGN ALIGN_86
#endif

//Define DEBUG_INFO for console output
//Define CUSTOM_PRINT (and DEBUG_INFO) to redirect the output to a custom window/file/control etc.
//With SetRawPrintCallback you can specify the callback to be called when a debug print occurs. The passed string is raw meaning all parameters have been parsed and converted.
//Call SetRawPrintCallback(nullptr) if you want to reset the callback pointer
//If both DEBUG_INFO and CUSTOM_PRINT are defined but no callback was passed to SetRawPrintCallback puts it's used instead

#define DEBUG_INFO
#define CUSTOM_PRINT
//#define DUMP_SHELLCODE

#ifdef DEBUG_INFO
using f_raw_print_callback = void(__stdcall *)(const char * szText);
inline f_raw_print_callback g_print_raw_callback = nullptr;

void custom_print(int indention_offset, const char * format, ...);
#else
using f_raw_print_callback = void *;
#endif

DWORD __stdcall SetRawPrintCallback(f_raw_print_callback print);

#ifdef DEBUG_INFO
	#define LOG custom_print
#else
	#define LOG
#endif