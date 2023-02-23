#pragma once

#include "pch.h"

#include "Injection.h"

//Stolen from here:
//https://www.codeproject.com/Articles/12585/The-NET-File-Format#GetStarted
//Really epic article!

#define DOT_NET_SIGNATURE 0x424A5342 //"BSJB"

struct DOTNET_META_DATA
{
	DWORD Signature; //"BSJB" or 0x424A5342

	WORD MajorVersion;
	WORD MinorVersion;

	DWORD ExtraDataRVA;

	DWORD VersionStringLength;
	char Version[ANYSIZE_ARRAY];
};

//ansi version of the .NET info structure:
struct DOTNET_INJECTIONDATAA
{
	char			szDllPath[MAX_PATH * 2];
	DWORD			ProcessID;
	INJECTION_MODE	Mode;
	LAUNCH_METHOD	Method;
	DWORD			Flags;
	DWORD			Timeout;
	DWORD			hHandleValue;
	HINSTANCE		hDllOut;
	bool			GenerateErrorLog;

	char szNamespace[128];	//namespace of the class in the target module
	char szClassName[128];	//name of the class in the target module
	char szMethodName[128];	//name of the method in the target module
	char szArgument[128];	//argument to be send to the method
};

//unicode version of the .NET info structure:
struct DOTNET_INJECTIONDATAW
{
	wchar_t			szDllPath[MAX_PATH * 2];
	DWORD			ProcessID;
	INJECTION_MODE	Mode;
	LAUNCH_METHOD	Method;
	DWORD			Flags;
	DWORD			Timeout;
	DWORD			hHandleValue;
	HINSTANCE		hDllOut;
	bool			GenerateErrorLog;

	wchar_t szNamespace[128];
	wchar_t szClassName[128];
	wchar_t szMethodName[128];
	wchar_t szArgument[128];
};

//.NET modules will be loaded with ExecuteInDefaultAppDomain.
//The injection settings will be applied to the .NET loader module (see GH Injector DNP).
//Since that module can't be mapped due to technical reasons it will be loaded using LdrpLoadDll.
//Furthermore the following flags will also be ignored:
/// INJ_LOAD_DLL_COPY
/// INJ_SCRAMBLE_DLL_NAME
/// INJ_UNLINK_FROM_PEB
/// INJ_FAKE_HEADER
/// INJ_ERASE_HEADER

DWORD __stdcall DotNet_InjectA(DOTNET_INJECTIONDATAA * pData);
DWORD __stdcall DotNet_InjectW(DOTNET_INJECTIONDATAW * pData);
//.NET injection functions (ansi/unicode).
//
//Arguments:
//		pData (DOTNET_INJECTIONDATAA/DOTNET_INJECTIONDATAW):
///			Pointer to the information structure for the injection.
//
//Returnvalue (DWORD):
///		On success: INJ_ERR_SUCCESS.
///		On failure: One of the errorcodes defined in Error.h.

//internal stuff, use it if you know what you're doing
struct DOTNET_INJECTIONDATA_INTERNAL
{
	std::wstring	DllPath;
	std::wstring	TargetProcessExeFileName;

	DWORD			ProcessID;
	INJECTION_MODE	Mode;
	LAUNCH_METHOD	Method;
	DWORD			Flags;
	DWORD			Timeout;
	DWORD			hHandleValue;
	HINSTANCE		hDllOut;
	bool			GenerateErrorLog;

	std::wstring Namespace;
	std::wstring ClassName;
	std::wstring MethodName;
	std::wstring Argument;
	std::wstring Version;

	DOTNET_INJECTIONDATA_INTERNAL(const DOTNET_INJECTIONDATAA * pData);
	DOTNET_INJECTIONDATA_INTERNAL(const DOTNET_INJECTIONDATAW * pData);
};

DWORD __stdcall DotNet_Inject_Internal(DOTNET_INJECTIONDATA_INTERNAL * pData);