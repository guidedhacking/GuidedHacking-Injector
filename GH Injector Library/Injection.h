#pragma once

#include "Eject.h"
#include "Handle Hijacking.h"
#include "Remote Function WOW64.h"

//Cloaking options:
#define INJ_ERASE_HEADER				0x0001	//replaces the first 0x1000 bytes of the dll with 0's (not compatible with INJ_FAKE_HEADER)
#define INJ_FAKE_HEADER					0x0002	//replaces the dlls header with the header of the local kernel32.dll (not compatible with INJ_ERASE_HEADER)
#define INJ_UNLINK_FROM_PEB				0x0004	//unlinks the module from the process enviroment block (1)
#define INJ_THREAD_CREATE_CLOAKED		0x0008	//passes certain flags to NtCreateThreadEx to make the thread creation more stealthy (2)
#define INJ_SCRAMBLE_DLL_NAME			0x0010	//randomizes the dll name on disk before injecting it
#define INJ_LOAD_DLL_COPY				0x0020	//loads a copy of the dll from %temp% directory
#define INJ_HIJACK_HANDLE				0x0040	//tries to a hijack a handle from another process instead of using OpenProcess

//Notes:
///(1) ignored when manual mapping
///(2) launch method must be NtCreateThreadEx, ignored otherwise

//Manual mapping options:
#define INJ_MM_SHIFT_MODULE				0x00010000	//shifts the module by a random amount of bytes - the data preceding the dll is randomized aswell
#define INJ_MM_CLEAN_DATA_DIR			0x00020000	//removes data from the dlls PE header
#define INJ_MM_RESOLVE_IMPORTS			0x00040000	//resolves dll imports
#define INJ_MM_RESOLVE_DELAY_IMPORTS	0x00080000	//resolves delayed imports
#define INJ_MM_EXECUTE_TLS				0x00100000	//executes TLS callbacks and initializes static TLS data
#define INJ_MM_ENABLE_SEH				0x00200000	//enables exception handling
#define INJ_MM_SET_PAGE_PROTECTIONS		0x00400000	//sets page protections based on section characteristics
#define INJ_MM_INIT_SECURITY_COOKIE		0x00800000	//initializes security cookie for buffer overrun protection
#define INJ_MM_RUN_DLL_MAIN				0x01000000	//executes DllMain
													//this option induces INJ_MM_RESOLVE_IMPORTS

#define MM_DEFAULT (INJ_MM_RESOLVE_IMPORTS | INJ_MM_EXECUTE_TLS | INJ_MM_ENABLE_SEH | INJ_MM_RUN_DLL_MAIN | INJ_MM_SET_PAGE_PROTECTIONS)

//ansi version of the info structure:
struct INJECTIONDATAA
{
	char			szDllPath[MAX_PATH * 2];					//fullpath to the dll to inject
	DWORD			ProcessID;									//process identifier of the target process
	INJECTION_MODE	Mode;										//injection mode
	LAUNCH_METHOD	Method;										//method to execute the remote shellcode
	DWORD			Flags;										//combination of the flags defined above
	DWORD			hHandleValue;								//optional value to identify a handle in a process
	HINSTANCE		hDllOut;									//returned image base of the injection
	bool			GenerateErrorLog;							//if true error data is generated and stored in GH_Inj_Log.txt
};

//unicode version of the info structure (documentation above).
//the additional member szTargetProcessExeFileName should be ignored since it's only used for error logging.
struct INJECTIONDATAW
{
	wchar_t			szDllPath[MAX_PATH * 2];
	wchar_t			szTargetProcessExeFileName[MAX_PATH];	//exe name of the target process, this value gets set automatically and should be initialized with 0s
	DWORD			ProcessID;
	INJECTION_MODE	Mode;
	LAUNCH_METHOD	Method;
	DWORD			Flags;
	DWORD			hHandleValue;
	HINSTANCE		hDllOut;
	bool			GenerateErrorLog;
};

DWORD __stdcall InjectA(INJECTIONDATAA * pData);
DWORD __stdcall InjectW(INJECTIONDATAW * pData);
//Main injection functions (ansi/unicode).
//
//Arguments:
//		pData (INJECTIONDATAA/INJECTIONDATAW):
///			Pointer to the information for the injection.
//
//Returnvalue (DWORD):
///		On success: INJ_ERR_SUCCESS.
///		On failure: One of the errorcodes defined in Error.h.

DWORD _LoadLibraryExW	(const wchar_t * szDllFile, HANDLE hTargetProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, ERROR_DATA & error_data);
DWORD _LdrLoadDll		(const wchar_t * szDllFile, HANDLE hTargetProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, ERROR_DATA & error_data);
DWORD _LdrpLoadDll		(const wchar_t * szDllFile, HANDLE hTargetProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, ERROR_DATA & error_data);
DWORD _ManualMap		(const wchar_t * szDllFile, HANDLE hTargetProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, ERROR_DATA & error_data);
//Injection methods called by InjectA/InjectW -> InjectDll

#ifdef _WIN64
DWORD InjectDLL_WOW64(const wchar_t * szDllFile, HANDLE hTargetProc, INJECTION_MODE im, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, ERROR_DATA & error_data);
//Main injection function when injecting from x64 into a WOW64 process.
//Arguments as defined in INJECTIONDATA and returnvalue as explained the InjectA/InjectW functions.

DWORD _LoadLibrary_WOW64	(const wchar_t * szDllFile, HANDLE hTargetProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, ERROR_DATA & error_data);
DWORD _LdrLoadDll_WOW64		(const wchar_t * szDllFile, HANDLE hTargetProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, ERROR_DATA & error_data);
DWORD _LdrpLoadDll_WOW64	(const wchar_t * szDllFile, HANDLE hTargetProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, ERROR_DATA & error_data);
DWORD _ManualMap_WOW64		(const wchar_t * szDllFile, HANDLE hTargetProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, ERROR_DATA & error_data);
//WOW64 injection methods called by InjectDLL_WOW64
#endif

#define MAXPATH_IN_TCHAR	MAX_PATH
#define MAXPATH_IN_BYTE_A	MAX_PATH * sizeof(char)
#define MAXPATH_IN_BYTE_W	MAX_PATH * sizeof(wchar_t)
#define MAXPATH_IN_BYTE		MAX_PATH * sizeof(TCHAR)
//Internal stuff

#define ALIGN_UP(X, A) (X + (A - 1)) & (~(A - 1))
#define ALIGN_IMAGE_BASE_X64(Base) ALIGN_UP(Base, 0x10)
#define ALIGN_IMAGE_BASE_X86(Base) ALIGN_UP(Base, 0x08)
#ifdef _WIN64 
#define ALIGN_IMAGE_BASE(Base) ALIGN_IMAGE_BASE_X64(Base)
#else
#define ALIGN_IMAGE_BASE(Base) ALIGN_IMAGE_BASE_X86(Base)
#endif
//Alignment macro for module and code bases