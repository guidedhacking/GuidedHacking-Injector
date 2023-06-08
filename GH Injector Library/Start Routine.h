#pragma once

#include "Process Info.h"
#include "Tools.h"

//Thread creation options:
#define INJ_CTF_FAKE_START_ADDRESS	0x00001000
#define INJ_CTF_HIDE_FROM_DEBUGGER	0x00002000
#define INJ_CTF_SKIP_THREAD_ATTACH	0x00004000
#define INJ_CTF_FAKE_TEB_CLIENT_ID	0x00008000
#define CTF_MASK (INJ_CTF_FAKE_START_ADDRESS | INJ_CTF_HIDE_FROM_DEBUGGER | INJ_CTF_SKIP_THREAD_ATTACH | INJ_CTF_FAKE_TEB_CLIENT_ID)

#define TEB_CLIENTID_64 0x40
#define TEB_CLIENTID_86 0x20

#ifdef _WIN64
#define TEB_CLIENTID TEB_CLIENTID_64
#else
#define TEB_CLIENTID TEB_CLIENTID_86
#endif

enum class SR_REMOTE_STATE : ULONG_PTR
{
	SR_RS_ExecutionPending	= 0,
	SR_RS_Executing			= 1,
	SR_RS_ExecutionFinished	= 2
};
//enum which is used to determine the state of the remote code

#ifdef _WIN64
using f_Routine			= DWORD(__fastcall *)(void * pArg);
using f_Routine_WOW64	= DWORD; //DWORD(__stdcall *)(void * pArg);
#else
using f_Routine = DWORD(__stdcall *)(void * pArg);
#endif

#define SR_REMOTE_DELAY 50
//small waiting period before checking remote results, probably not necessary

#define KERNEL_CALLBACK_TABLE_SIZE 200

ALIGN struct SR_REMOTE_DATA
{
	ALIGN SR_REMOTE_STATE	State			= SR_REMOTE_STATE::SR_RS_ExecutionPending;
	ALIGN DWORD				Ret				= 0;
	ALIGN DWORD				LastWin32Error	= 0;
	ALIGN void *			pArg			= nullptr;
	ALIGN f_Routine			pRoutine		= nullptr;
	ALIGN UINT_PTR			Buffer			= 0;
};

ALIGN struct SR_REMOTE_DATA_VEH
{
	SR_REMOTE_DATA Data{ };

	ALIGN f_LdrProtectMrdata	pLdrProtectMrdata	= nullptr;
	ALIGN LIST_ENTRY	*		pListHead			= nullptr;
	ALIGN LIST_ENTRY	*		pFakeEntry			= nullptr;
	ALIGN bool					bRemoveVEHBit		= false;
};

#define PTR_64_ARR 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
#define PTR_86_ARR 0x00, 0x00, 0x00, 0x00,

#define SR_REMOTE_DATA_BUFFER_64 PTR_64_ARR PTR_64_ARR PTR_64_ARR PTR_64_ARR PTR_64_ARR PTR_64_ARR
#define SR_REMOTE_DATA_BUFFER_86 PTR_86_ARR PTR_86_ARR PTR_86_ARR PTR_86_ARR PTR_86_ARR PTR_86_ARR

#define SR_REMOTE_DATA_BUFFER_VEH_64 SR_REMOTE_DATA_BUFFER_64 PTR_64_ARR PTR_64_ARR PTR_64_ARR PTR_64_ARR
#define SR_REMOTE_DATA_BUFFER_VEH_86 SR_REMOTE_DATA_BUFFER_86 PTR_86_ARR PTR_86_ARR PTR_86_ARR PTR_86_ARR

#ifdef _WIN64
	#define SR_REMOTE_DATA_BUFFER SR_REMOTE_DATA_BUFFER_64
	#define SR_REMOVE_DATA_BUFFER_VEH SR_REMOTE_DATA_BUFFER_VEH_64
#else
	#define SR_REMOTE_DATA_BUFFER SR_REMOTE_DATA_BUFFER_86
	#define SR_REMOVE_DATA_BUFFER_VEH SR_REMOTE_DATA_BUFFER_VEH_86
#endif

DWORD StartRoutine(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, LAUNCH_METHOD Method, DWORD Flags, DWORD & Out, DWORD Timeout, ERROR_DATA & error_data);
//Executes shellcode in the target process.
//
//Arguments:
//		hTargetProc (HANDLE):
///			A handle to the target process. Access rights depend on the launch method. PROCESS_ALL_ACCESS is the best option here.
//		pRoutine (f_Routine):
///			A pointer to the shellcode in the virtual memory of the target process.
//		pArg (void *):
///			A pointer to the argument which gets passed to the shellcode.
//		Method (LAUNCH_METHOD):
///			A LAUNCH_METHOD enum which defines the method to be used when executing the shellcode.
//		Flags (DWORD):
///			The injection flags contain cloaking options for NtCreateThreadEx.
//		LastWin32Error (DWORD &):
///			A reference to a DWORD which can be used to store an errorcode if something goes wrong. Otherwise it's INJ_ERROR_SUCCESS (0).
//		hOut (ULONG_PTR &):
///			A reference to a ULONG_PTR which is used to store the returned value of the shellcode. This can be changed into any datatype (a 32 bit type on x86 and a 64 bit type on x64).
//		Timeout (DWORD):
///			The time the method waits for the shellcode to finish executing in milliseconds.
//
//Returnvalue (DWORD):
///		On success: 0 (INJ_ERR_SUCCESS).
///		On failure:	An errorcode from Error.h (start routine section).

DWORD SR_NtCreateThreadEx	(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD Flags,				DWORD & Out, DWORD Timeout, ERROR_DATA & error_data);
DWORD SR_HijackThread		(HANDLE hTargetProc, f_Routine pRoutine, void * pArg,							DWORD & Out, DWORD Timeout, ERROR_DATA & error_data);
DWORD SR_SetWindowsHookEx	(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, ULONG TargetSessionId,	DWORD & Out, DWORD Timeout, ERROR_DATA & error_data);
DWORD SR_QueueUserAPC		(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, 							DWORD & Out, DWORD Timeout, ERROR_DATA & error_data);
DWORD SR_KernelCallback		(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, ULONG TargetSessionId,	DWORD & Out, DWORD Timeout, ERROR_DATA & error_data);
DWORD SR_FakeVEH			(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, 							DWORD & Out, DWORD Timeout, ERROR_DATA & error_data);
//Subroutines called by StartRoutine.

#ifdef _WIN64
ALIGN_86 struct SR_REMOTE_DATA_WOW64
{
	ALIGN_86 DWORD State			= 0;
	ALIGN_86 DWORD Ret				= 0;
	ALIGN_86 DWORD LastWin32Error	= 0;
	ALIGN_86 DWORD pArg				= 0;
	ALIGN_86 DWORD pRoutine			= 0;
	ALIGN_86 DWORD Buffer			= 0;
};

ALIGN_86 struct SR_REMOTE_DATA_VEH_WOW64
{
	SR_REMOTE_DATA_WOW64 Data{ };

	ALIGN_86 DWORD pLdrProtectMrdata	= 0;
	ALIGN_86 DWORD pListHead			= 0;
	ALIGN_86 DWORD pFakeEntry			= 0;
	ALIGN_86 DWORD bRemoveVEHBit		= 0;
};

#define SR_REMOTE_DATA_BUFFER_WOW64 SR_REMOTE_DATA_BUFFER_86

DWORD StartRoutine_WOW64(HANDLE hTargetProc, f_Routine_WOW64 pRoutine, DWORD pArg, LAUNCH_METHOD Method, DWORD Flags, DWORD & Out, DWORD Timeout, ERROR_DATA & error_data);
//Equivalent of StartRoutine when injecting from x64 into a WOW64 process. For documentation check the comments on StartRoutine.

DWORD SR_NtCreateThreadEx_WOW64	(HANDLE hTargetProc, f_Routine_WOW64 pRoutine, DWORD pArg, DWORD Flags,				DWORD & Out, DWORD Timeout, ERROR_DATA & error_data);
DWORD SR_HijackThread_WOW64		(HANDLE hTargetProc, f_Routine_WOW64 pRoutine, DWORD pArg,							DWORD & Out, DWORD Timeout, ERROR_DATA & error_data);
DWORD SR_SetWindowsHookEx_WOW64	(HANDLE hTargetProc, f_Routine_WOW64 pRoutine, DWORD pArg, ULONG TargetSessionId,	DWORD & Out, DWORD Timeout, ERROR_DATA & error_data);
DWORD SR_QueueUserAPC_WOW64		(HANDLE hTargetProc, f_Routine_WOW64 pRoutine, DWORD pArg,							DWORD & Out, DWORD Timeout, ERROR_DATA & error_data);
DWORD SR_KernelCallback_WOW64	(HANDLE hTargetProc, f_Routine_WOW64 pRoutine, DWORD pArg, ULONG TargetSessionId,	DWORD & Out, DWORD Timeout, ERROR_DATA & error_data);
DWORD SR_FakeVEH_WOW64			(HANDLE hTargetProc, f_Routine_WOW64 pRoutine, DWORD pArg,							DWORD & Out, DWORD Timeout, ERROR_DATA & error_data);
//Subroutines called by StartRoutine_WOW64.
#endif