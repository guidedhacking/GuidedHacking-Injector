//Include this file if you want to use the injection library in your own project
//
//Use LoadLibrary to import the injection library:
//HINSTANCE hInjectionMod = LoadLibrary(GH_INJ_MOD_NAME);
//
//Grab the injection functions with GetProcAddress:
//auto InjectA = (f_InjectA)GetProcAddress(hInjectionMod, "InjectA");
//auto InjectW = (f_InjectW)GetProcAddress(hInjectionMod, "InjectW");
//
//If needed:
//auto ValidateInjectionFunctions	= (f_ValidateInjectionFunctions)GetProcAddress(hInjectionMod, "ValidateInjectionFunctions");
//auto RestorenjectionFunctions		= (f_RestoreInjectionFunctions)GetProcAddress(hInjectionMod, "RestorenjectionFunctions");
//
//Symbol state:
//auto GetSymbolState 		= (f_GetSymbolState)GetProcAddress(hInjectionMod, "GetSymbolState");
//auto GetDownloadProgress 	= (f_GetDownloadProgress)GetProcAddress(hInjectionMod, "GetDownloadProgress");

#pragma once

#define GH_INJ_VERSIONW L"4.6"
#define GH_INJ_VERSIONA "4.6"

#define GH_INJ_MOD_NAME64W L"Libx64.dll"
#define GH_INJ_MOD_NAME86W L"Libx86.dll"

#define GH_INJ_MOD_NAME64A "Libx64.dll"
#define GH_INJ_MOD_NAME86A "Libx86.dll"

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

#include <Windows.h>

enum class INJECTION_MODE
{
	IM_LoadLibraryExW,
	IM_LdrLoadDll,
	IM_LdrpLoadDll,
	IM_LdrpLoadDllInternal,
	IM_ManualMap
};

enum class LAUNCH_METHOD
{
	LM_NtCreateThreadEx,
	LM_HijackThread,
	LM_SetWindowsHookEx,
	LM_QueueUserAPC,
	LM_KernelCallback,
	LM_FakeVEH
};

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

//unicode version of the info structure (documentation above)
struct INJECTIONDATAW
{
	wchar_t			szDllPath[MAX_PATH * 2];
	wchar_t			szTargetProcessExeFileName[MAX_PATH];	//exe name of the target process, this value gets set automatically and should be initialized with 0s
	DWORD			ProcessID;
	INJECTION_MODE	Mode;
	LAUNCH_METHOD	Method;
	DWORD			Flags;
	DWORD			Timeout;
	DWORD			hHandleValue;
	HINSTANCE		hDllOut;
	bool			GenerateErrorLog;
};

#ifdef _UNICODE
#define INJECTIONDATA INJECTIONDATAW
#else
#define INJECTIONDATA INJECTIONDATAA
#endif

//amount of bytes to be scanned by ValidateInjectionFunctions and restored by RestoreInjectionFunctions
#define HOOK_SCAN_BYTE_COUNT 0x10

//ValidateInjectionFunctions fills an std::vector with this info, result can simply be passed to RestoreInjectionFunctions
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

//Cloaking options:
#define INJ_ERASE_HEADER				0x0001	//replaces the first 0x1000 bytes of the dll with 0's (takes priority over INJ_FAKE_HEADER if both are specified)
#define INJ_FAKE_HEADER					0x0002	//replaces the dlls header with the header of the ntdll.dll (superseded by INJ_ERASE_HEADER if both are specified)
#define INJ_UNLINK_FROM_PEB				0x0004	//unlinks the module from the process enviroment block (1)
#define INJ_THREAD_CREATE_CLOAKED		0x0008	//passes certain flags to NtCreateThreadEx to make the thread creation more stealthy (2)
#define INJ_SCRAMBLE_DLL_NAME			0x0010	//randomizes the dll name on disk before injecting it
#define INJ_LOAD_DLL_COPY				0x0020	//loads a copy of the dll from %temp% directory
#define INJ_HIJACK_HANDLE				0x0040	//tries to a hijack a handle from another process instead of using OpenProcess

//Notes:
///(1) ignored when manual mapping
///(2) launch method must be NtCreateThreadEx, ignored otherwise

//Manual mapping options:
#define INJ_MM_CLEAN_DATA_DIR			0x00010000	//removes data from the dlls PE header, ignored if INJ_MM_SET_PAGE_PROTECTIONS is set
#define INJ_MM_RESOLVE_IMPORTS			0x00020000	//resolves dll imports
#define INJ_MM_RESOLVE_DELAY_IMPORTS		0x00040000	//resolves delayed imports
#define INJ_MM_EXECUTE_TLS			0x00080000	//executes TLS callbacks and initializes static TLS data
#define INJ_MM_ENABLE_EXCEPTIONS		0x00100000	//enables exception handling
#define INJ_MM_SET_PAGE_PROTECTIONS		0x00200000	//sets page protections based on section characteristics, if set INJ_MM_CLEAN_DATA_DIR will be ignored
#define INJ_MM_INIT_SECURITY_COOKIE		0x00400000	//initializes security cookie for buffer overrun protection
#define INJ_MM_RUN_DLL_MAIN			0x00800000	//executes DllMain
								//this option induces INJ_MM_RESOLVE_IMPORTS
#define INJ_MM_RUN_UNDER_LDR_LOCK		0x01000000	//runs the DllMain under the loader lock
#define INJ_MM_SHIFT_MODULE_BASE		0x02000000	//shifts the module base by a random offset

#define MM_DEFAULT (INJ_MM_RESOLVE_IMPORTS | INJ_MM_RESOLVE_DELAY_IMPORTS | INJ_MM_INIT_SECURITY_COOKIE | INJ_MM_EXECUTE_TLS | INJ_MM_ENABLE_EXCEPTIONS | INJ_MM_RUN_DLL_MAIN | INJ_MM_SET_PAGE_PROTECTIONS)

//Arguments for GetDownloadProgressEx
#define PDB_DOWNLOAD_INDEX_NTDLL	(int)0 //ntdll pdb download
#define PDB_DOWNLOAD_INDEX_KERNEL32 (int)1 //kernel32 pdb download (Windows 7 only)

INJECTION_MODE GetInjMode(int InjectMode)
{
	
switch (InjectMode)  {
    case 0:
	 return INJECTION_MODE::IM_LoadLibraryExW;
		break;
  case 1:
       return  INJECTION_MODE::IM_LdrLoadDll;
		break;
	 case 2:
       return  INJECTION_MODE::IM_LdrpLoadDll;
		break;
	 case 3:
       return  INJECTION_MODE::IM_LdrpLoadDllInternal;
		break;
	 case 4:
       return  INJECTION_MODE::IM_ManualMap;
		break;
    default:
       return  INJECTION_MODE::IM_LoadLibraryExW;
}
}

LAUNCH_METHOD GetLchMehod(int LMethod)
{
	
switch (LMethod)  {
    case 0:
	  return  LAUNCH_METHOD::LM_NtCreateThreadEx;
	  break;
  case 1:
         return  LAUNCH_METHOD::LM_HijackThread;
		break;
	 case 2:
          return  LAUNCH_METHOD::LM_SetWindowsHookEx;
		break;
	 case 3:
       return  LAUNCH_METHOD::LM_QueueUserAPC;
		break;
	 case 4:
       return  LAUNCH_METHOD::LM_KernelCallback;
		break;
 case 5:
    return  LAUNCH_METHOD::LM_FakeVEH;
		break;
    default:
       return  LAUNCH_METHOD::LM_NtCreateThreadEx;
}

}