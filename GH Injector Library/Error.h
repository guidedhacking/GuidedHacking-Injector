#pragma once

/// ###############	##########		##########		     #######	   ##########			###			###
/// ###############	############	############	  ####     ####    ############			###			###
/// ###				###        ###	###        ###	 ###         ###   ###        ###		###			###
/// ###				###        ###	###        ###	###           ###  ###        ###		###			###
/// ###				###       ###	###       ###	###           ###  ###       ###		###			###
/// ###############	###########		###########		###           ###  ###########			###############
/// ###############	###########		########### 	###			  ###  ###########			###############
/// ###				###      ###	###		###     ###			  ###  ###		###			###			###
/// ###				###		  ###	###		  ###	###           ###  ###		  ###		###			###
/// ###				###		   ###	###		   ###	 ###         ###   ###		   ###	 #	###			###
/// ###############	###		   ###	###		   ###	  ####     ####    ###		   ###  ###	###			###
/// ###############	###        ###	###        ###	     #######	   ###         ###   #	###			###

//Injection errors:
#define INJ_ERR_SUCCESS					0x00000000
#define INJ_ERR_ADVANCED_NOT_DEFINED	0x00000000
													
														//Source							: advanced error type	: error description

#define INJ_ERR_NO_DATA						0x00000001	//internal error					: -						: nullptr passed to InjectA/InjectW
#define INJ_ERR_INVALID_FILEPATH			0x00000002	//internal error					: -						: INJECTIONDATA::szDllPath is a nullptr
#define INJ_ERR_STR_CONVERSION_TO_W_FAILED	0x00000003	//mbstowcs_s						: errno_t				: conversion to unicode of an ansi string failed
#define INJ_ERR_STRINGC_XXX_FAIL			0x00000004	//StringCXXX failed					: HRESULT				: string operation failed
#define INJ_ERR_FILE_DOESNT_EXIST			0x00000005	//GetFileAttributesW				: win32 error			: INJECTIONDATA::szDllPath doesn't exist
#define INJ_ERR_INVALID_PID					0x00000006	//internal error					: -						: provided process id is 0
#define INJ_ERR_CANT_OPEN_PROCESS			0x00000007	//OpenProcess						: win32 error			: opening the specified target process failed
#define INJ_ERR_INVALID_PROC_HANDLE			0x00000008	//GetHandleInformation				: win32 error			: the provided handle value is not a valid handle
#define INJ_ERR_CANT_GET_EXE_FILENAME		0x00000009	//(K32)GetModuleBaseNameW			: win32 error			: failed to resolve the file name of the target process
#define INJ_ERR_PLATFORM_MISMATCH			0x0000000A	//internal error					: file error			: the provided file can't be injected (file error 0x20000001 - 0x20000003)
#define INJ_ERR_CANT_GET_TEMP_DIR			0x0000000B	//GetTempPathW						: win32 error			: unable to retrieve the path to the current users temp directory
#define INJ_ERR_CANT_COPY_FILE				0x0000000C	//CopyFileW							: win32 error			: unable to create a copy of the specified dll file
#define INJ_ERR_CANT_RENAME_FILE			0x0000000D	//_wrename							: errno					: renaming the file failed
#define INJ_ERR_INVALID_INJ_METHOD			0x0000000E	//bruh moment						: bruh moment			: bruh moment
#define INJ_ERR_REMOTE_CODE_FAILED			0x0000000F	//internal error					: -						: the remote code wasn't able to load the specified module
#define INJ_ERR_WPM_FAIL					0x00000010	//WriteProcessMemory				: win32 error			: write operation failed
#define	INJ_ERR_RPM_FAIL					0x00000011	//ReadProcessMemory					: win32 error			: read operation failed
#define INJ_ERR_GET_MODULE_HANDLE_FAIL		0x00000012	//GetModuleHandle					: win32 error			: address of the specified module couldn't be resolved
#define INJ_ERR_CANT_FIND_MOD_PEB			0x00000013	//internal error					: -						: injected module isn't linked to the peb
#define INJ_ERR_CANT_ACCESS_PEB_LDR			0x00000014	//ReadProcessMemory					: win32 error			: reading the peb entry of the injected module failed
#define INJ_ERR_OUT_OF_MEMORY_EXT			0x00000015	//VirtualAllocEx					: win32 error			: memory allocation in the target process failed
#define INJ_ERR_OUT_OF_MEMORY_INT			0x00000016	//VirtualAlloc						: win32 error			: internal memory allocation failed
#define INJ_ERR_OUT_OF_MEMORY_NEW			0x00000017	//operator new						: -						: internal memory allocation on heap failed
#define INJ_ERR_IMAGE_CANT_RELOC			0x00000018	//internal error					: -						: image has to be relocated but base reloc directory is emtpy
#define INJ_ERR_LDRLOADDLL_MISSING			0x00000019	//internal error					: -						: can't resolve the address of LdrLoadDll
#define INJ_ERR_REMOTEFUNC_MISSING			0x0000001A	//internal error					: -						: can't resolve the address of a remote function
#define INJ_ERR_VERIFY_RESULT_FAIL			0x0000001B	//ReadProcessMemory					: win32 error			: reading the result data of the injection failed
#define INJ_ERR_CANT_SET_PAGE_PROT			0x0000001C	//VirtualProtectEx					: win32 error			: updating the page protections failed
#define INJ_ERR_MODULE_MISSING				0x0000001D	//GetModuleHandle					: win32 error			: resolving the address of a required module failed
#define INJ_ERR_REMOTEMODULE_MISSING		0x0000001E	//GetModuleHandleEx(WOW64)			: -						: resolving the address of a required module in the target process failed
#define INJ_ERR_SYMBOL_INIT_NOT_DONE		0x0000001F	//SYMBOL_PARSER::Initialize			: -						: initializations process of the symbol parser isn't finished
#define INJ_ERR_SYMBOL_INIT_FAIL			0x00000020	//SYMBOL_PARSER::Initialize			: symbol error			: initialization failed (symbol error 0x40000001 - 0x40000014)
#define INJ_ERR_SYMBOL_GET_FAIL				0x00000021	//SYMBOL_PARSER::GetSymbolAddress	: symbol error			: couldn't get address of required symbol (symbol error 0x40000001 - 0x40000014)
#define INJ_ERR_LOAD_CONFIG_EMPTY			0x00000022	//internal error					: -						: the load configuration directory of the module is emtpy
#define INJ_ERR_CANT_GET_MODULE_PATH		0x00000023	//internal error					: -						: can't resolve the path of this instance of the injection library
#define INJ_ERR_FAILED_TO_LOAD_DLL			0x00000024	//internal error					: -						: the injection failed for unknown reasons
#define INJ_ERR_HIJACK_NO_HANDLES			0x00000025	//internal error					: -						: can't find a process handle to the target process
#define INJ_ERR_HIJACK_NO_NATIVE_HANDLE		0x00000026	//internal error					: -						: can't find a hijackable handle to the target process
#define INJ_ERR_HIJACK_INJ_FAILED			0x00000027	//internal error					: GH Inj error code		: injecting injection module into handle owner process failed
#define INJ_ERR_HIJACK_OUT_OF_MEMORY_EXT	0x00000028	//VirtualAllocEx					: win32 error			: memory allocation in the hijack process failed
#define INJ_ERR_HIJACK_WPM_FAIL				0x00000029	//WriteProcessMemory				: win32 error			: writing injection data to hijack process failed
#define INJ_ERR_HIJACK_INJECTW_MISSING		0x0000002A	//internal error					: -						: can't locate remote injection function in hijack process
#define INJ_ERR_HIJACK_REMOTE_INJ_FAIL		0x0000002B	//internal error					: GH Inj error code		: injection executed in the hijack process failed, additional error log was generated

///////////////////
///LoadLibraryExW
											//Source				: advanced error type	: error description

#define INJ_LLEXW_ERR_NO_DATA	0x00100001	//LoadLibraryExW_Shell	: -						: pData is NULL
#define INJ_LLEXW_ERR_INV_DATA	0x00100002	//LoadLibraryExW_Shell	: -						: pData is invalid
#define INJ_LLEXW_ERR_LL_FAIL	0x00100003	//LoadLibraryExW_Shell	: -						: pData->pLoadLibraryExW returned NULL

///////////////////
///LdrLoadDll
											//Source			: advanced error type	: error description

#define INJ_LLDLL_ERR_NO_DATA	0x00200001	//LdrLoadDll_Shell	: -						: pData is NULL
#define INJ_LLDLL_ERR_INV_DATA	0x00200002	//LdrLoadDll_Shell	: -						: pData is invalid
#define INJ_LLDLL_ERR_LL_FAIL	0x00200003	//LdrLoadDll_Shell	: NTSTATUS  			: pData->pLdrLoadDll failed

///////////////////
///LdrpLoadDll
											//Source			: advanced error type	: error description

#define INJ_LDRPL_ERR_NO_DATA	0x00300001	//LdrpLoadDll_Shell	: -						: pData is NULL
#define INJ_LDRPL_ERR_INV_DATA	0x00300002	//LdrpLoadDll_Shell	: -						: pData is invalid
#define INJ_LDRPL_ERR_LL_FAIL	0x00300003	//LdrpLoadDll_Shell	: NTSTATUS				: pData->pLdrpLoadDll failed

///////////////////
///ManualMap
															//Source				: advanced error type	: error description

#define INJ_MM_ERR_NO_DATA						0x00400001	//ManualMapping_Shell	: -						: pData is NULL
#define INJ_MM_LOADLIBRARYA_MISSING				0x00400002	//ManualMapping_Shell	: -						: can't resolve imports because pLoadLibraryA is NULL
#define INJ_MM_GETMODULEHANDLEA_MISSING			0x00400003	//ManualMapping_Shell	: -						: can't resolve imports because pGetModuleHandleA is NULL
#define INJ_MM_GETPROCADDRESS_MISSING			0x00400004	//ManualMapping_Shell	: -						: can't resolve imports because pGetProcAddress is NULL
#define INJ_MM_CANT_LOAD_MODULE					0x00400005	//ManualMapping_Shell	: -						: GetModuleHandleA and LoadLibraryA failed
#define INJ_MM_CANT_GET_IMPORT					0x00400006	//ManualMapping_Shell	: -						: GetProcAddress failed
#define INJ_MM_CANT_LOAD_DELAY_MODULE			0x00400007	//ManualMapping_Shell	: -						: can't load required delayed module (GetModuleHandleA and LoadLibraryA failed)
#define INJ_MM_CANT_GET_DELAY_IMPORT			0x00400008	//ManualMapping_Shell	: -						: can't load required delayed import (GetProcAddress failed)
#define INJ_MM_KERNEL32_POINTER_MISSING			0x00400009	//ManualMapping_Shell	: -						: can't fake PE header since kernel32.dll reference is missing
#define INJ_MM_FUNCTION_TABLE_MISSING			0x0040000A	//ManualMapping_Shell	: -						: function pointer to RtlInsertInvertedFunctionTable is missing
#define INJ_MM_ENABLING_SEH_FAILED				0x0040000B	//ManualMapping_Shell	: -						: RtlInsertInvertedFunctionTable failed



/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


//Start Routine errors:
#define SR_ERR_SUCCESS					0x00000000
													
													//Source					: advanced error type	: error description
 
#define SR_ERR_CANT_QUERY_SESSION_ID	0x10000001	//NtQueryInformationProcess	: NTSTATUS				: querying the session id of the target process failed
#define SR_ERR_INVALID_LAUNCH_METHOD	0x10000002	//bruh moment				: bruh moment			: bruh moment
#define SR_ERR_NOT_LOCAL_SYSTEM			0x10000003	//internal error			: -						: SetWindowsHookEx with handle hijacking only works within the same session or from session 0 (LocalSystem account) because of the WtsAPIs


///////////////////
///NtCreateThreadEx
														//Source					: advanced error type	: error description

#define SR_NTCTE_ERR_NTCTE_MISSING			0x10100001	//internal error			: -						: can't resolve address of NtCreateThreadEx
#define SR_NTCTE_ERR_PROC_INFO_FAIL			0x10100002	//internal error			: -						: can't grab process information
#define SR_NTCTE_ERR_CANT_ALLOC_MEM			0x10100003	//VirtualAllocEx			: win32 error			: memory allocation for the shellcode failed
#define SR_NTCTE_ERR_WPM_FAIL				0x10100004	//WriteProcessMemory		: win32 error			: writing the shellcode into the target process' memory failed
#define SR_NTCTE_ERR_NTCTE_FAIL				0x10100005	//NtCreateThreadEx			: NTSTATUS				: thread creation using NtCreateThreadEx failed
#define SR_NTCTE_ERR_GET_CONTEXT_FAIL		0x10100006	//(Wow64)GetThreadContext	: win32 error			: can't get thread context
#define SR_NTCTE_ERR_SET_CONTEXT_FAIL		0x10100007	//(Wow64)SetThreadContext	: win32 error			: can't set thread context
#define SR_NTCTE_ERR_RESUME_FAIL			0x10100008	//ResumeThread				: win32 error			: resuming the thread failed
#define SR_NTCTE_ERR_REMOTE_TIMEOUT			0x10100009	//WaitForSingleObject		: win32 error			: execution time of the shellcode exceeded SR_REMOTE_TIMEOUT
#define SR_NTCTE_ERR_GECT_FAIL				0x1010000A	//GetExitCodeThread			: win32 error			: can't retrieve the exit code of the thread
#define SR_NTCTE_ERR_SHELLCODE_SETUP_FAIL	0x1010000B	//shellcode					: - 					: argument passed to the shellcode is 0
#define SR_NTCTE_ERR_RPM_FAIL				0x1010000C	//ReadProcessMemory			: win32 error			: reading the results of the shellcode failed

///////////////
///HijackThread
														//Source					: advanced error type	: error description

#define SR_HT_ERR_PROC_INFO_FAIL			0x10200001	//internal error			: -						: can't grab process information
#define SR_HT_ERR_NO_THREADS				0x10200002	//internal error			: -						: no threads to hijack
#define SR_HT_ERR_OPEN_THREAD_FAIL			0x10200003	//OpenThread				: win32 error			: can't open handle to the target thread
#define SR_HT_ERR_SUSPEND_FAIL				0x10200004	//SuspendThread				: win32 error			: suspending the target thread failed
#define SR_HT_ERR_GET_CONTEXT_FAIL			0x10200005	//(Wow64)GetThreadContext	: win32 error			: can't get thread context
#define SR_HT_ERR_CANT_ALLOC_MEM			0x10200006	//VirtualAllocEx			: win32 error			: memory allocation for the shellcode failed
#define SR_HT_ERR_WPM_FAIL					0x10200007	//WriteProcessMemory		: win32 error			: writing the shellcode into the target process' memory failed
#define SR_HT_ERR_SET_CONTEXT_FAIL			0x10200008	//(Wow64)SetThreadContext	: win32 error			: can't update the thread context
#define SR_HT_ERR_RESUME_FAIL				0x10200009	//ResumeThread				: win32 error			: resuming the thread failed
#define SR_HT_ERR_REMOTE_TIMEOUT			0x1020000A	//internal error			: -						: execution time exceeded SR_REMOTE_TIMEOUT (can't be deallocated safely)
#define SR_HT_ERR_REMOTE_PENDING_TIMEOUT	0x1020000B	//internal error			: -						: execution time exceeded SR_REMOTE_TIMEOUT while pending (can be deallocated safely)

////////////////////
///SetWindowsHookEx
														//Source				:	error description

#define SR_SWHEX_ERR_CANT_QUERY_INFO_PATH	0x10300001	//internal error		:	can't resolve own module filepath
#define SR_SWHEX_ERR_CANT_OPEN_INFO_TXT		0x10300002	//internal error		:	can't open swhex info file
#define SR_SWHEX_ERR_VAE_FAIL				0x10300003	//VirtualAllocEx		:	win32 error
#define SR_SWHEX_ERR_CNHEX_MISSING			0x10300004	//GetProcAddressEx		:	can't find pointer to CallNextHookEx
#define SR_SWHEX_ERR_WPM_FAIL				0x10300005	//WriteProcessMemory	:	win32 error
#define SR_SWHEX_ERR_WTSQUERY_FAIL			0x10300006	//WTSQueryUserToken		:	win32 error
#define SR_SWHEX_ERR_DUP_TOKEN_FAIL			0x10300007	//DuplicateTokenEx		:	win32 error
#define SR_SWHEX_ERR_GET_ADMIN_TOKEN_FAIL	0x10300008	//GetTokenInformation	:	win32 error
#define SR_SWHEX_ERR_CANT_CREATE_PROCESS	0x10300009	//CreateProcessAsUserW	:	win32 error
														//CreateProcessW		:	win32 error
#define SR_SWHEX_ERR_SWHEX_TIMEOUT			0x1030000A	//WaitForSingleObject	:	win32 error
#define SR_SWHEX_ERR_SWHEX_EXT_ERROR		0x1030000B	//SM_EXE_FILENAME.exe	:	"GH Injector SM - XX.exe" error code, 0x30100001 - 0x30100006 (see below) or win32 exception
#define SR_SWHEX_ERR_REMOTE_TIMEOUT			0x1030000C	//internal error		:	execution time exceeded SR_REMOTE_TIMEOUT

///////////////
///QueueUserAPC
														//Source					: advanced error type	: error description

#define SR_QUAPC_ERR_RTLQAW64_MISSING		0x10400001	//internal error			: -						: can't resolve address of RtlQueueApcWow64Thread
#define SR_QUAPC_ERR_CANT_ALLOC_MEM			0x10400002	//VirtualAllocEx			: win32 error			: memory allocation for the shellcode failed
#define SR_QUAPC_ERR_WPM_FAIL				0x10400003	//WriteProcessMemory		: win32 error			: writing the shellcode into the target process' memory failed
#define SR_QUAPC_ERR_PROC_INFO_FAIL			0x10400004	//internal error			: -						: can't grab process information
#define SR_QUAPC_ERR_NO_THREADS				0x10400005	//internal error			: -						: no threads to queue an apc to
#define SR_QUAPC_ERR_REMOTE_TIMEOUT			0x10400006	//internal error			: -						: execution time exceeded SR_REMOTE_TIMEOUT (can be deallocated safely)



/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


//File errors:
#define FILE_ERR_SUCCESS			0x00000000

												//Source				:	error description
#define FILE_ERR_CANT_OPEN_FILE		0x20000001	//std::ifstream::good	:	openening the file failed
#define FILE_ERR_INVALID_FILE_SIZE	0x20000002	//internal error		:	file isn't a valid PE
#define FILE_ERR_INVALID_FILE		0x20000003	//internal error		:	PE isn't compatible with the injection settings



/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//GH Injector SM - XX.exe errors:

												//Source	:	error description

#define SM_ERR_INVALID_ARGC	0x30000001			//main		:	GH Injector SM - XX.exe was called with the wrong amount of arguments
#define SM_ERR_INVALID_ARGV	0x30000002			//main		:	GH Injector SM - XX.exe was called with invalid arguments

////////////////////////////////////////////////////////////
///GH Injector SM - XX.exe - SetWindowsHookEx specific erros:
#define SWHEX_ERR_SUCCESS			0x00000000

												//Source				:	error description

#define SWHEX_ERR_INVALID_PATH		0x30100001	//StringCchLengthW		:	path exceeds MAX_PATH * 2 chars
#define SWHEX_ERR_CANT_OPEN_FILE	0x30100002	//std::ifstream::good	:	openening the SMXX.txt failed
#define SWHEX_ERR_EMPTY_FILE		0x30100003	//internal error		:	SMXX.txt is empty
#define SWHEX_ERR_INVALID_INFO		0x30100004	//internal error		:	provided info is wrong / invalid
#define SWHEX_ERR_ENUM_WINDOWS_FAIL 0x30100005	//EnumWindows			:	API fail
#define SWHEX_ERR_NO_WINDOWS		0x30100006	//internal error		:	no compatible window found



/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


//Symbol errors:
#define SYMBOL_ERR_SUCCESS						0x00000000

															//Source				:	error description
#define SYMBOL_ERR_CANT_OPEN_MODULE				0x40000001	//std::ifstream::good	:	can't open the specified module
#define SYMBOL_ERR_FILE_SIZE_IS_NULL			0x40000002	//std::ifstream::tellg	:	file size of the specified module is 0
#define SYMBOL_ERR_CANT_ALLOC_MEMORY_NEW		0x40000003	//operator new			:	can't allocate memory
#define SYMBOL_ERR_INVALID_FILE_ARCHITECTURE	0x40000004	//internal error		:	the architecture of the specified file doesn't match AMD64 or I386
#define SYMBOL_ERR_CANT_ALLOC_MEMORY			0x40000005	//VirtualAlloc			:	can't allocate memory
#define SYMBOL_ERR_NO_PDB_DEBUG_DATA			0x40000006	//internal error		:	debuge directory is emtpy or wrong type
#define SYMBOL_ERR_PATH_DOESNT_EXIST			0x40000007	//CreateDirectoryA		:	path doesn't exit and can't be created
#define SYMBOL_ERR_CANT_CREATE_DIRECTORY		0x40000008	//CreateDirectoryA		:	path doesn't exit and can't be created (x86/x64 subdirectory)
#define SYMBOL_ERR_CANT_CONVERT_PDB_GUID		0x40000008	//StringFromGUID2		:	conversion of the GUID to string failed
#define SYMBOL_ERR_GUID_TO_ANSI_FAILED			0x40000009	//wcstombs_s			:	conversion of GUID to ANSI string failed
#define SYMBOL_ERR_DOWNLOAD_FAILED				0x4000000A	//URLDownloadToFileA	:	downloading the pdb file failed
#define SYMBOL_ERR_CANT_ACCESS_PDB_FILE			0x4000000B	//GetFileAttributesExA	:	can't access the pdb file
#define SYMBOL_ERR_CANT_OPEN_PDB_FILE			0x4000000C	//CreateFileA			:	can't open the pdb file
#define SYMBOL_ERR_CANT_OPEN_PROCESS			0x4000000D	//OpenProcess			:	can't open handle to current process
#define SYMBOL_ERR_SYM_INIT_FAIL				0x4000000E	//SymInitialize			:	couldn't initialize pdb symbol stuff
#define SYMBOL_ERR_SYM_LOAD_TABLE				0x4000000F	//SymLoadModule64		:	couldn't load symbol table
#define SYMBOL_ERR_ALREADY_INITIALIZED			0x40000010	//internal error		:	this instance of the SYMBOL_PARSER has already been initialized
#define SYMBOL_ERR_NOT_INITIALIZED				0x40000011	//internal error		:	this isntance of the SYMBOL_PARSER hasn't benen initialized
#define SYMBOL_ERR_IVNALID_SYMBOL_NAME			0x40000012	//internal error		:	szSymbolName is NULL
#define SYMBOL_ERR_SYMBOL_SEARCH_FAILED			0x40000013	//SymFromName			:	couldn't find szSymbolName in the specified pdb
#define SYMBOL_CANT_OPEN_PROCESS				0x40000014	//OpenProcess			:	can't get PROCESS_QUERY_LIMITED_INFORMATION handle to current process



/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


//Symbol errors:
#define HOOK_SCAN_ERR_SUCCESS						0x00000000

																//Source				:	error description
#define HOOK_SCAN_ERR_INVALID_PROCESS_ID			0x50000001	//internal error		:	target process identifier is 0
#define HOOK_SCAN_ERR_CANT_OPEN_PROCESS				0x50000002	//OpenProcess			:	target process identifier is 0
#define HOOK_SCAN_ERR_PLATFORM_MISMATCH				0x50000003	//internal error		:	wow64 injector can't scan x64 process
#define HOOK_SCAN_ERR_GETPROCADDRESS_FAILED			0x50000004	//GetProcAddress		:	GetProcAddress failed internally
#define HOOK_SCAN_ERR_READ_PROCESS_MEMORY_FAILED	0x50000005	//ReadProcessMemory		:	ReadProcessMemory failed while reading the bytes of the target function
#define HOOK_SCAN_ERR_CANT_GET_OWN_MODULE_PATH		0x50000006	//GetOwnModulePath		:	unable to obtain path to the GH Injector directory
#define HOOK_SCAN_ERR_CREATE_EVENT_FAILED			0x50000007	//CreateEventEx			:	win32 error
#define HOOK_SCAN_ERR_CREATE_PROCESS_FAILED			0x50000008	//CreateProcessW		:	win32 error
#define HOOK_SCAN_ERR_WAIT_FAILED					0x50000009	//WaitForSingleObject	:	win32 error
#define HOOK_SCAN_ERR_WAIT_TIMEOUT					0x5000000A	//WaitForSingleObject	:	waiting timed out

struct ERROR_DATA
{
	DWORD		AdvErrorCode;
	wchar_t		szFileName[MAX_PATH];
	wchar_t		szFunctionName[MAX_PATH];
	int			Line;
};

#define INIT_ERROR_DATA(data, error) \
data.AdvErrorCode = error;\
data.Line = __LINE__; \
memcpy(data.szFileName, __FILENAMEW__,  ((size_t)lstrlenW(__FILENAMEW__)) * 2); \
memcpy(data.szFunctionName, __FUNCTIONW__, ((size_t)lstrlenW(__FUNCTIONW__)) * 2);