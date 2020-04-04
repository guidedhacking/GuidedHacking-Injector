#pragma once

#include "Start Routine.h"

void EjectDll(HANDLE hTargetProc, HINSTANCE hModBase);
//Unloads a Dll using FreeLibrary by creating a thread in the target process using NtCreateThreadEx.
//
//Arguments:
//		hTargetProc (HANDLE):
///			HANDLE to the target process which needs:
///				PROCESS_CREATE_THREAD
///				PROCESS_QUERY_INFORMATION
///				PROCESS_VM_OPERATION
///				PROCESS_VM_WRITE
///				PROCESS_VM_READ
//		hModBase (HINSTANCE):
///			The baseaddress of the module to unload.
//
//Returnvalue:
///		void