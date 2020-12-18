#pragma once

#include "Import Handler.h"

//Filenames and errorlog setup

#define GH_INJ_MOD_NAME64W L"GH Injector - x64.dll"
#define GH_INJ_MOD_NAME86W L"GH Injector - x86.dll"
#define GH_INJ_VERSIONW L"4.0"

#define GH_INJ_MOD_NAME64A "GH Injector - x64.dll"
#define GH_INJ_MOD_NAME86A "GH Injector - x86.dll"
#define GH_INJ_VERSIONA "4.0"

#ifdef _WIN64
#define GH_INJ_MOD_NAMEW GH_INJ_MOD_NAME64W
#define GH_INJ_MOD_NAMEA GH_INJ_MOD_NAME64A
#else
#define GH_INJ_MOD_NAMEW GH_INJ_MOD_NAME86W
#define GH_INJ_MOD_NAMEA GH_INJ_MOD_NAME86A
#endif

#ifdef UNICODE
#define GH_INJ_MOD_NAME GH_INJ_MOD_NAMEW
#define GH_INJ_VERSION GH_INJ_VERSIONW
#else
#define GH_INJ_MOD_NAME GH_INJ_MOD_NAMEA
#define GH_INJ_VERSION GH_INJ_VERSIONA
#endif

//Global variable to store the base address of the current image of the injector. Initialized in DllMain.
inline HINSTANCE g_hInjMod = NULL;

//Global variables to store the root directory of the module
inline std::string	g_RootPathA;
inline std::wstring	g_RootPathW;

struct ERROR_INFO
	//A structure used to pass information to the error log function.
{
	const wchar_t *	szDllFileName;
	const wchar_t * szTargetProcessExeFileName;
	DWORD			TargetProcessId;
	INJECTION_MODE	InjectionMode;
	LAUNCH_METHOD	LaunchMethod;
	DWORD			Flags;
	DWORD			ErrorCode;
	DWORD			AdvErrorCode;
	DWORD			HandleValue;
	int				bNative;
	const wchar_t * szSourceFile;
	const wchar_t * szFunctionName;
	int				Line;
};

bool FileExists(const wchar_t * szFile);
//A function to quickly check whether a file exists or not.
//
//Arguments:
//		szFile (const wchar_t*):
///			Pointer to a string containing the full path to the file.
//
//Returnvalue (bool):
///		true:	the file exists.
///		false:	the file doesn't exist.

DWORD ValidateFile(const wchar_t * szFile, DWORD desired_machine);
//A function used to verify whether the file fits the requirements of current injection settings.
//
//Arguments:
//		szFile (const wchar_t*):
///			Pointer to a string containing the full path to the file.
//		desired_machine (DWORD):
///			A value to be compared to the Machine member of the files IMAGE_FILE_HEADER	.
//
//Returnvalue (DWORD):
///		On success: 0.
///		On failure: an errocode from Error.h.

bool GetOwnModulePathA(char		* pOut, size_t BufferCchSize);
bool GetOwnModulePathW(wchar_t	* pOut, size_t BufferCchSize);
//A function to get the filepath to the file of this image of the injector.
//
//Arguments:
//		pOut (TCHAR*):
///			Pointer to a widechar buffer to contain the full path.
//		BufferCchSize (size_t):
///			Size of the buffer in characters.
//
//Returnvalue (bool):
///		true:	pOut now contains the path.
///		false:	error enumerating the modules.

bool IsNativeProcess(HANDLE hTargetProc);
//A function to determine whether a process runs natively or under WOW64.
//
//Arguments:
//		hTargetProc (HANDLE):
///			A handle to the desired process. This handle must have the PROCESS_QUERY_LIMITED_INFORMATION or PROCESS_QUERY_INFORMATION access right.
//
//Returnvalue (bool):
///		true: the specified process runs natively.
///		false: the specified process doesn't run natively.

ULONG GetSessionId(HANDLE hTargetProc, NTSTATUS & ntRetOut);
//A function to retrieve the session identifier of a process.
//
//Arguments:
//		hTargetproc (HANDLE):
///			A handle to the desired process. This handle must have the PROCESS_QUERY_LIMITED_INFORMATION or PROCESS_QUERY_INFORMATION access right.
//		ntRetOut (NTSTATUS &):
///			A reference to an NTSTATUS variable which will receive the returnvalue of NtQueryInformationProcess.
//
//Returnvalue (ULONG):
//		On success: The session identifier of the specified process.
//		On failuer: -1, check ntRetOut for more information.

bool IsElevatedProcess(HANDLE hTargetProc);
//A function used to determine whether a process is running elevated or not (administrator vs. user).
//
//Arguments:
//		hTargetproc (HANDLE):
///			A handle to the desired process. This handle must have the PROCESS_QUERY_INFORMATION access right.
//
//Returnvalue (bool):
///		true:	process is elevated.
///		false:	process is not elevated.

void ErrorLog(ERROR_INFO * info);
//A function used to generate an error log file in case shit hit the fan for some reason.
//
//Arguments:
//		info (ERROR_INFO*):
///			A pointer to an ERROR_INFO structure which contains information about what went wrong.
//
//Returnvalue (void)

#if !defined(_WIN64) && defined(DUMP_SHELLCODE)

void DumpShellcode(BYTE * start, int length, const wchar_t * szShellname);

#endif

float __stdcall GetDownloadProgress(bool bWow64);
//This function returns the current state of the PDB download.
//
//Arguments:
//		bWow64 (bool):
///			If true the progress of the WoW64 PDB download will be returned, otherwise the progress of the native pdb download.
//
//Returnvalue (float):
///		A value 0 <= ret <= 1. 1 indicates that the download is finished.