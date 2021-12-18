#pragma once

#include "Import Handler.h"

#define INJ_EJECT_TIMEOUT 200

bool EjectDll(HANDLE hTargetProc, HINSTANCE hModule, bool WOW64 = false);
//Unloads a dll using LdrUnloadDll by creating a thread in the target process using NtCreateThreadEx (native only).
//
//Arguments:
//		hTargetProc (HANDLE):
///			HANDLE to the target process which needs:
///				PROCESS_CREATE_THREAD
///				PROCESS_QUERY_INFORMATION
///				PROCESS_VM_OPERATION
///				PROCESS_VM_WRITE
///				PROCESS_VM_READ
//		hModule (HINSTANCE):
///			The baseaddress of the module to unload.
//		WOW64 (bool):
///			Set to true if the target process is running under WOW64 and the calling process is native.
///			If the calling process is not native this argument is ignored.
//
//Returnvalue (bool):
///		true:	the module was unloaded successfully.
///		false:	something went wrong, see logs

bool EjectHijackLibrary(HANDLE hTargetProc, HINSTANCE hInjectionModuleEx, bool Interrupt = true);
//Unloads the injection library from another process during handle hijacking.
//
//Arguments:
//		hTargetProc (HANDLE):
///			HANDLE to the target process which needs:
///				PROCESS_CREATE_THREAD
///				PROCESS_QUERY_INFORMATION
///				PROCESS_VM_OPERATION
///				PROCESS_VM_WRITE
///				PROCESS_VM_READ
//		hInjectionModuleEx (HINSTANCE):
///			The baseaddress of the injection library in the target process.
//		Interrupt (bool):
///			If set to true InterruptDownloadEx is called remotely before unloading the dll.
//
//Returnvalue (bool):
///		true:	the module was unloaded successfully.
///		false:	something went wrong, see logs