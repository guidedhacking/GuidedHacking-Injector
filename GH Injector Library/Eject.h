#pragma once

#include "Import Handler.h"

bool EjectDll(HANDLE hTargetProc, HINSTANCE hModule);
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
//
//Returnvalue (bool):
///		true:	the module was unloaded successfully.
///		false:	something went wrong, see logs