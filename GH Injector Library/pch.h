#pragma once

#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING //ur mom

//winapi shit
#include <Windows.h>

//enum shit
#include <TlHelp32.h>
#include <Psapi.h>

//string shit
#include <codecvt> 
#include <string>
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

//internet shit
#include <WinInet.h>

//warning shit
#pragma warning(disable: 4201) //unnamed union
#pragma warning(disable: 4324) //structure member alignment resulting in additional bytes being added as padding
#pragma warning(disable: 6001) //uninitialized memory & handles (false positive in for loops with continue statements)
#pragma warning(disable: 6258) //TerminateThread warning
//#pragma warning(disable: 6387) //pointer could be 0 (false positive in "Manual Mapping WOW64.cpp")

//reinterpret_cast = too long to type
#define ReCa reinterpret_cast

//Macro to convert 32-bit DWORD into void*.
#define MPTR(d) (void*)(ULONG_PTR)d

//Macro to convert void* into 32-bit DWORD.
#define MDWD(p) (DWORD)((ULONG_PTR)p & 0xFFFFFFFF)

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
	LM_QueueUserAPC
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

#ifdef CUSTOM_PRINT
using f_raw_print_callback = void(__stdcall *)(const char * szText);
inline f_raw_print_callback g_print_raw_callback = nullptr;
void custom_print(const char * format, ...);
#else
using f_raw_print_callback = void*;
#endif

DWORD __stdcall SetRawPrintCallback(f_raw_print_callback print);

#ifdef DEBUG_INFO
	#ifdef CUSTOM_PRINT
		#define LOG custom_print
	#else
		#define LOG printf
	#endif
#else
	#define LOG
#endif