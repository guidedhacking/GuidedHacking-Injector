/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

#pragma once

#include "pch.h"

#include "Error.h"
#include "NT Defs.h"
#include "NT Funcs.h"

//Filenames

#define GH_INJ_MOD_NAME64W L"GH Injector - x64.dll"
#define GH_INJ_MOD_NAME86W L"GH Injector - x86.dll"
#define GH_INJ_VERSIONW L"4.8"

#define GH_INJ_MOD_NAME64A "GH Injector - x64.dll"
#define GH_INJ_MOD_NAME86A "GH Injector - x86.dll"
#define GH_INJ_VERSIONA "4.8"

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

//Global macro round up addresses and offsets
#define ALIGN_UP(X, A) ((ULONG_PTR)X + (A - 1)) & (~(A - 1))

//String stuff
#define MAXPATH_IN_TCHAR	MAX_PATH
#define MAXPATH_IN_BYTE_A	MAX_PATH * sizeof(char)
#define MAXPATH_IN_BYTE_W	MAX_PATH * sizeof(wchar_t)
#define MAXPATH_IN_BYTE		MAX_PATH * sizeof(TCHAR)

#define PDB_DOWNLOAD_INDEX_NTDLL	(int)0
#define PDB_DOWNLOAD_INDEX_KERNEL32 (int)1

#define SESSION_ID_INVALID		(ULONG)-1
#define SESSION_ID_LOCAL_SYSTEM (ULONG)0

//Global variable to store the base address of the current image of the injector. Initialized in DllMain.
inline HINSTANCE g_hInjMod = NULL;

struct ERROR_INFO
	//A structure used to pass information to the error log function.
{
	std::wstring	DllFileName;
	std::wstring	TargetProcessExeFileName;
	DWORD			TargetProcessId;
	INJECTION_MODE	InjectionMode;
	LAUNCH_METHOD	LaunchMethod;
	DWORD			Flags;
	DWORD			ErrorCode;
	DWORD			AdvErrorCode;
	DWORD			HandleValue;
	int				bNative;
	std::wstring	SourceFile;
	std::wstring	FunctionName;
	int				Line;

	//from memory only
	BYTE *	RawData;
	DWORD	RawSize;

	//.NET only
	bool			IsDotNet;
	std::wstring	Version;
	std::wstring	Namespace;
	std::wstring	ClassName;
	std::wstring	Method;
	std::wstring	Argument;	
};

struct INJECTION_SOURCE
{
	std::wstring DllPath;

	BYTE *	RawData		= nullptr;
	DWORD	RawSize		= 0;
	bool	FromMemory	= false;
};

//Global variable to store the root directory of the module (including '\\' at the end)
inline std::wstring	g_RootPathW;

inline DWORD g_OSVersion = 0;
inline DWORD g_OSBuildNumber = 0;

#define g_Win7	61
#define g_Win8	62
#define g_Win81	63
#define g_Win10	100
#define g_Win11	100

#define g_Win7_SP1 7601
#define g_Win8_SP1 9600
#define g_Win10_1507 10240
#define g_Win10_1511 10586
#define g_Win10_1607 14393
#define g_Win10_1703 15063
#define g_Win10_1709 16299
#define g_Win10_1803 17134
#define g_Win10_1809 17763
#define g_Win10_1903 18362
#define g_Win10_1909 18363
#define g_Win10_2004 19041
#define g_Win10_20H2 19042
#define g_Win10_21H1 19043
#define g_Win10_21H2 19044
#define g_Win10_22H2 19045
#define g_Win11_21H2 22000
#define g_Win11_22H2 22621

bool IsWin7OrGreater();
bool IsWin8OrGreater();
bool IsWin81OrGreater();
bool IsWin10OrGreater();
bool IsWin11OrGreater();
//These functions are used to determine the currently running version of windows. GetNTDLLVersion needs to be successfully called before these work.
//
//Arguements:
//		none
//
//Returnvalue (bool):
///		true:	Running OS is equal or newer than specified in the function name.
///		false:	Running OS is older than specified in the function name.

DWORD GetOSVersion(DWORD * error_code = nullptr);
//This function is used to determine the version of the operating system.
// 
//Arguments:
//		errode_code (DWORD *):
///			A reference to a DWORD which will receive an error code if the function fails (optional).
//
//Returnvalue (DWORD):
///		On success:	The version of the operating system to 1 decimal place (multiplied by 10 as an integer)
///		On failure:	0.

DWORD GetOSBuildVersion();
//This function is used to determine the build version of the operating system.
// 
//Arguments:
//		none
//
//Returnvalue (DWORD):
///		On success:	The build version of the operating system.
///		On failure:	0.
/// 
bool FileExistsW(const std::wstring & FilePath);
//A function to quickly check whether a file exists or not.
//
//Arguments:
//		FilePath (const std::wstring &):
///			A reference to an std::wstring object which contains the path to the to be verified file.
//
//Returnvalue (bool):
///		true:	the file exists.
///		false:	the file doesn't exist.

DWORD ValidateDllFile(const std::wstring & FilePath, DWORD target_machine);
//A function used to verify whether the file fits the requirements of current injection settings.
//
//Arguments:
//		FilePath (const std::wstring &):
///			A reference to an std::wstring object containing the full path to the file.
//		target_machine (DWORD):
///			A value to be compared to the Machine member of the files IMAGE_FILE_HEADER.
//
//Returnvalue (DWORD):
///		On success: 0.
///		On failure: an errocode from Error.h.

DWORD ValidateDllFileInMemory(const BYTE * RawData, DWORD RawSize, DWORD target_machine);
//A function used to verify whether the file in memory fits the requirements of current injection settings.
//
//Arguments:
//		FilePath (const BYTE * ):
///			A pointer to the raw data of the file.
//		RawSize (DWORD):
///			The size of the raw data in bytes.
//		target_machine (DWORD):
///			A value to be compared to the Machine member of the files IMAGE_FILE_HEADER.
//
//Returnvalue (DWORD):
///		On success: 0.
///		On failure: an errocode from Error.h.

bool GetOwnModulePathA(std::string & out);
bool GetOwnModulePathW(std::wstring & out);
//A function to get the filepath to the file of this image of the injector.
//
//Arguments:
//		out (std::(w)string &):
///			A reference to an std::(w)string object which will recieve the path.
//
//Returnvalue (bool):
///		true:	out now contains the path.
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
///		On success: The session identifier of the specified process.
///		On failure: -1, check ntRetOut for more information.

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

void ErrorLog(const ERROR_INFO & info);
//A function used to generate an error log file in case shit hit the fan for some reason.
//
//Arguments:
//		info (ERROR_INFO *):
///			A pointer to an ERROR_INFO structure which contains information about what went wrong.
//
//Returnvalue (void)

std::wstring CharArrayToStdWstring(const char * szString);
//A function to easily convert an ascii string to a unicode string.
//
//Arguments:
//		szString (const char *)
///			A pointer to a zero terminated ascii string.
//
//Returnvalue (std::wstring):
///		The converted wstring object.

bool StdWStringToWCharArray(const std::wstring & Source, wchar_t * szBuffer, size_t Size);
//This function copies the content of an std::wstring into a wchar_t array of a given size.
//
//Arguments:
//		Source (const std::wstring &):
///			A reference to a string object to be copied.
//		szBuffer (wchar_t *):
///			A pointer to a wchar_t array to be filled with the content of the source string.
//		Size (size_t):
///			The maximum amount of characters to be copied into buffer.
//
//Returnvalue (bool):
///		true: the string has been copied successfully.
///		false: the provided buffer is too small or one of the arguments was invalid.

#if !defined(_WIN64) && defined(DUMP_SHELLCODE)
//Rad function to dump the injection / mapping shells to paste them into "WOW64 Shells.h"
void DumpShellcode(BYTE * start, int length, const wchar_t * szShellname);

//Terrible macro to do terrible things
#define DUMP_WOW64(start, end) DumpShellcode(ReCa<BYTE *>(start), ReCa<BYTE *>(end) - ReCa<BYTE *>(start), L#start L"_WOW64")
#endif

float __stdcall GetDownloadProgress(bool bWow64);
//This function returns the current state of the ntdll PDB download. This function is provided for downward compatibility only. Use GetDownloadProgressEx instead.
//
//Arguments:
//		bWow64 (bool):
///			If true the progress of the WoW64 PDB download will be returned, otherwise the progress of the native pdb download.
//
//Returnvalue (float):
///		A value 0 <= ret <= 1. 1 indicates that the download is finished.

float __stdcall GetDownloadProgressEx(int index, bool bWow64);
//This function returns the current state of the PDB download.
//
//Arguments:
//		index (int):
//			Index of the dll download:
//				PDB_DOWNLOAD_INDEX_NTDLL	(0): ntdll
//				PDB_DOWNLOAD_INDEX_KERNEL32 (1): kernel32 (Windows 7 only)
//		bWow64 (bool):
///			If true the progress of the WoW64 PDB download will be returned, otherwise the progress of the native pdb download.
//
//Returnvalue (float):
///		A value 0 <= ret <= 1. 1 indicates that the download is finished.

void __stdcall StartDownload();
//Starts the download(s) of the PDB file(s).
// 
//Arguments:
//		none
//
//Returnvalue (void)

void __stdcall InterruptDownload();
//Interrupts the download(s) of the PDB file(s). This function returns after all download/imports threads were interrupted.
// 
//Arguments:
//		none
//
//Returnvalue (void)

DWORD __stdcall InterruptDownloadEx(void * pArg);
//A wrapper function for InterruptDownload that is compatible with the f_Routine prototype (and thus compatible with StartRoutine and Create(Remote)Thread/NtCreateThreadEx etc.).
//
//Arguments:
//		pArg (void *):
///			This argument is ignored.
//
//Returnvalue (DWORD):
///		This function returns 0.

bool __stdcall InterruptInjection(DWORD Timeout);
//Interrupts the injection. This can lead to shit hitting the fan really hard and is not recommended.
//
//Arguments:
//		Timeout (DWORD):
///			Timeout in ms for the function to wait to verify that the injection was interrupted.
//
//Returnvalue (bool):
///		true:	the injection thread was interrupted successfully.
///		false:	interrupt failed.

DWORD __stdcall InterruptInjectionEx(void * Timeout);
//A wrapper function for InterruptInjection that is compatible with the f_Routine prototype (and thus compatible with StartRoutine and Create(Remote)Thread/NtCreateThreadEx etc.).
//
//Arguments:
//		Timeout (void *):
///			Not a pointer!
///				On x64: the low 32 bit define the timeout in ms
///				On x86: the timeout in ms
//
//Returnvalue (DWORD):
///		non zero:	the injection thread was interrupted successfully.
///		0:			interrupted failed.

DWORD CreateTempFileCopy(std::wstring & FilePath, DWORD & win32err);
//Simple function to create a copy of a file in the %TEMP% directory.
//
//Arguments:
//		FilePath (std::wstring &):
///			The path to the copied file.
///			On success this variable will recieve the new path.
//		win32errr (DWORD &):
///			A reference to DWORD value which will receive a win32 error code on failure.
//
//Returnvalue (DWORD):
///		On success: FILE_ERR_SUCCESS (0)
///		On failure: an error code specified in Error.h

DWORD ScrambleFileName(std::wstring & FilePath, UINT Length, DWORD & win32err);
//Simple function to scramble the name of an existing file.
//
//Arguments:
//		FilePath (std::wstring &):
///			The path to the renamed file.
///			On success this variable will recieve the new path.
//		Length (UINT):
///			Length of the new name in characters excluding the file extension.
//		win32errr (DWORD &):
///			A reference to DWORD value which will receive a win32 error code on failure.
//
//Returnvalue (DWORD):
///		On success: FILE_ERR_SUCCESS (0)
///		On failure: an error code specified in Error.h