#pragma once

#include "Import Handler.h"

struct handle_data
{
	DWORD	OwnerPID;
	WORD	hValue;
	DWORD	Access;
};
//Structure to store data when enumerating handles.

std::vector<handle_data> FindProcessHandles(DWORD TargetPID, DWORD WantedHandleAccess);
//Used to find handles for a specific process
//
//Arguments:
//		TargetPID (DWORD):
///			Process identifier of the target process
//		WantedHandleAccess (DWORD):
///			Combination of process access rights:
//			https://docs.microsoft.com/en-gb/windows/desktop/ProcThread/process-security-and-access-rights
//
//Returnvalue:
///		On success: std::vector of handle_data structs which contain information on the handles
///		On failure: empty vector