#pragma once

#include "Injection Internal.h"
#include "Eject.h"
#include "Handle Hijacking.h"

//Cloaking options:
#define INJ_ERASE_HEADER				0x0001	//replaces the first 0x1000 bytes of the dll with 0's (takes priority over INJ_FAKE_HEADER if both are specified)
#define INJ_FAKE_HEADER					0x0002	//replaces the dlls header with the header of the ntdll.dll (superseded by INJ_ERASE_HEADER if both are specified)
#define INJ_UNLINK_FROM_PEB				0x0004	//unlinks the module from the process enviroment block (1)
#define INJ_THREAD_CREATE_CLOAKED		0x0008	//induces INJ_CTF_FAKE_START_ADDRESS | INJ_CTF_HIDE_FROM_DEBUGGER (2), see "Start Routine.h" for all options
#define INJ_SCRAMBLE_DLL_NAME			0x0010	//randomizes the dll name on disk before injecting it
#define INJ_LOAD_DLL_COPY				0x0020	//loads a copy of the dll from %temp% directory
#define INJ_HIJACK_HANDLE				0x0040	//tries to a hijack a handle from another process instead of using OpenProcess

//Notes:
///(1) ignored when manual mapping
///(2) launch method must be NtCreateThreadEx, ignored otherwise

//Manual mapping options:
#define INJ_MM_CLEAN_DATA_DIR			0x00010000	//removes data from the dlls PE header, ignored if INJ_MM_SET_PAGE_PROTECTIONS is set
#define INJ_MM_RESOLVE_IMPORTS			0x00020000	//resolves dll imports
#define INJ_MM_RESOLVE_DELAY_IMPORTS	0x00040000	//resolves delayed imports
#define INJ_MM_EXECUTE_TLS				0x00080000	//executes TLS callbacks and initializes static TLS data
#define INJ_MM_ENABLE_EXCEPTIONS		0x00100000	//enables exception handling
#define INJ_MM_SET_PAGE_PROTECTIONS		0x00200000	//sets page protections based on section characteristics, if set INJ_MM_CLEAN_DATA_DIR and INJ_MM_SHIFT_MODULE_BASE will be ignored
#define INJ_MM_INIT_SECURITY_COOKIE		0x00400000	//initializes security cookie for buffer overrun protection
#define INJ_MM_RUN_DLL_MAIN				0x00800000	//executes DllMain
													//this option induces INJ_MM_RESOLVE_IMPORTS
#define INJ_MM_RUN_UNDER_LDR_LOCK		0x01000000	//runs the DllMain under the loader lock
#define INJ_MM_SHIFT_MODULE_BASE		0x02000000	//shifts the module base by a random offset, ignored if INJ_MM_SET_PAGE_PROTECTIONS is set
#define INJ_MM_MAP_FROM_MEMORY			0x04000000	//loads the file from memory instead of from disk (1)
#define INJ_MM_LINK_MODULE				0x08000000	//links the module to the PEB

//Notes:
///(1) only works with Memory_Inject and is set automatically when that function is used, ignored when passed to (DotNet_)InjectA/W

#define MM_DEFAULT (INJ_MM_RESOLVE_IMPORTS | INJ_MM_RESOLVE_DELAY_IMPORTS | INJ_MM_INIT_SECURITY_COOKIE | INJ_MM_EXECUTE_TLS | INJ_MM_ENABLE_EXCEPTIONS | INJ_MM_RUN_DLL_MAIN | INJ_MM_SET_PAGE_PROTECTIONS | INJ_MM_RUN_UNDER_LDR_LOCK)
#define MM_MASK (MM_DEFAULT | INJ_MM_SHIFT_MODULE_BASE | INJ_MM_CLEAN_DATA_DIR | INJ_MM_MAP_FROM_MEMORY | INJ_MM_LINK_MODULE)

//ansi version of the info structure:
struct INJECTIONDATAA
{
	char			szDllPath[MAX_PATH * 2];	//fullpath to the dll to inject
	DWORD			ProcessID;					//process identifier of the target process
	INJECTION_MODE	Mode;						//injection mode
	LAUNCH_METHOD	Method;						//method to execute the remote shellcode
	DWORD			Flags;						//combination of the flags defined above
	DWORD			Timeout;					//timeout for DllMain return in milliseconds
	DWORD			hHandleValue;				//optional value to identify a handle in a process
	HINSTANCE		hDllOut;					//returned image base of the injection
	bool			GenerateErrorLog;			//if true error data is generated and stored in GH_Inj_Log.txt
};

//unicode version of the info structure (documentation above).
struct INJECTIONDATAW
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
};

DWORD __stdcall InjectA(INJECTIONDATAA * pData);
DWORD __stdcall InjectW(INJECTIONDATAW * pData);
//Main injection functions (ansi/unicode).
//
//Arguments:
//		pData (INJECTIONDATAA/INJECTIONDATAW *):
///			Pointer to the information structure for the injection.
//
//Returnvalue (DWORD):
///		On success: INJ_ERR_SUCCESS.
///		On failure: One of the errorcodes defined in Error.h.

//use this to load a file from memory (manual mapping only, other methods will be ignored, make sure to set appropriate manual mapping flags)
struct MEMORY_INJECTIONDATA
{
	BYTE *			RawData;	//pointer to raw file data
	DWORD			RawSize;	//size in bytes of RawData
	DWORD			ProcessID;
	INJECTION_MODE	Mode;
	LAUNCH_METHOD	Method;
	DWORD			Flags;
	DWORD			Timeout;
	DWORD			hHandleValue;
	HINSTANCE		hDllOut;
	bool			GenerateErrorLog;
};

DWORD __stdcall Memory_Inject(MEMORY_INJECTIONDATA * pData);
//From memory injection function.
//
//Arguments:
//		pData (MEMORY_INJECTIONDATA *):
///			Pointer to the information structure for the injection
//
//Returnvalue (DWORD):
///		On success: INJ_ERR_SUCCESS.
///		On failure: One of the errorcodes defined in Error.h.

//Internal stuff
#define INJ_HIJACK_TIMEOUT	250

//Returns the version string of the current instance
HRESULT __stdcall GetVersionA(char		* out, size_t cb_size);
HRESULT __stdcall GetVersionW(wchar_t	* out, size_t cb_size);

//Returns the state of the symbol download threads
//If finished SYMBOL_ERR_SUCCESS (0) is returned 
//If still in progress INJ_ERR_SYMBOL_INIT_NOT_DONE (0x1C) is returned.
//Other error codes are defined in Error.h.
DWORD __stdcall GetSymbolState();

//Returns the state of the import handler.
//If finished INJ_ERR_SUCCESS (0) is returned.
//If still in progress INJ_ERR_IMPORT_HANDLER_NOT_DONE (0x37) is returned.
//Other error codes are defined in Error.h.
DWORD __stdcall GetImportState();

//internal stuff, use it if you know what you're doing
struct INJECTIONDATA_INTERNAL
{
	std::wstring	DllPath;
	std::wstring	TargetProcessExeFileName;

	BYTE *			RawData;
	DWORD			RawSize;

	DWORD			ProcessID;
	INJECTION_MODE	Mode;
	LAUNCH_METHOD	Method;
	DWORD			Flags;
	DWORD			Timeout;
	DWORD			hHandleValue;
	HINSTANCE		hDllOut;
	bool			GenerateErrorLog;

	INJECTIONDATA_INTERNAL(const INJECTIONDATAA			* pData);
	INJECTIONDATA_INTERNAL(const INJECTIONDATAW			* pData);
	INJECTIONDATA_INTERNAL(const MEMORY_INJECTIONDATA	* pData);
	INJECTIONDATA_INTERNAL();
};

DWORD __stdcall Inject_Internal(INJECTIONDATA_INTERNAL * pData);