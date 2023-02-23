#include "pch.h"

#include "Handle Hijacking.h"

NTSTATUS EnumHandles(char * pBuffer, ULONG Size, ULONG * SizeOut, UINT & Count);
std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO> EnumProcessHandles();

NTSTATUS EnumHandles(char * pBuffer, ULONG Size, ULONG * SizeOut, UINT & Count)
{
	NTSTATUS ntRet = NATIVE::NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemHandleInformation, pBuffer, Size, SizeOut);

	if (NT_FAIL(ntRet))
	{
		LOG(4, "Failed to grab handle list: %08X\n", ntRet);

		return ntRet;
	}

	auto * pHandleInfo = ReCa<SYSTEM_HANDLE_INFORMATION *>(pBuffer);
	Count = pHandleInfo->NumberOfHandles;
	
	LOG(4, "%d handles found\n", Count);

	return ntRet;
}

std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO> EnumProcessHandles()
{
	std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO> Ret;
	UINT Count		= 0;
	ULONG Size		= 0x10000;
	char * pBuffer	= new(std::nothrow) char[Size]();

	if (pBuffer == nullptr)
	{
		return Ret;
	}

	NTSTATUS ntRet = EnumHandles(pBuffer, Size, &Size, Count);

	if (NT_FAIL(ntRet))
	{
		while (ntRet == STATUS_INFO_LENGTH_MISMATCH)
		{
			delete[] pBuffer;
			pBuffer = new(std::nothrow) char[Size];

			if (pBuffer == nullptr)
			{
				return Ret;
			}

			ntRet = EnumHandles(pBuffer, Size, &Size, Count);
		}

		if (NT_FAIL(ntRet))
		{
			delete[] pBuffer;

			return Ret;
		}
	}

	auto * pEntry = ReCa<SYSTEM_HANDLE_INFORMATION *>(pBuffer)->Handles;
	for (UINT i = 0; i != Count; ++i)
	{
		if ((OBJECT_TYPE_NUMBER)pEntry[i].ObjectTypeIndex == OBJECT_TYPE_NUMBER::Process)
		{
			Ret.push_back(pEntry[i]);
		}
	}
		
	delete[] pBuffer;

	return Ret;
}

std::vector<handle_data> FindProcessHandles(DWORD TargetPID, DWORD WantedHandleAccess)
{
	std::vector<handle_data> Ret;
	DWORD OwnPID = GetCurrentProcessId();

	auto handles = EnumProcessHandles();

	LOG(2, "%d process handles found\n", (DWORD)handles.size());

	auto current_process = GetCurrentProcess();

	for (const auto & i : handles)
	{
		DWORD CurrentPID = i.UniqueProcessId;
		if (CurrentPID == OwnPID || CurrentPID == TargetPID)
		{
			continue;
		}

		HANDLE hCurrentProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, CurrentPID);
		if (!hCurrentProc)
		{
			continue;
		}

		if ((i.GrantedAccess & WantedHandleAccess) != WantedHandleAccess)
		{
			continue;
		}

		HANDLE hDup		= nullptr;
		HANDLE hOrig	= ReCa<HANDLE>(i.HandleValue);
		
		if (DuplicateHandle(hCurrentProc, hOrig, current_process, &hDup, PROCESS_QUERY_LIMITED_INFORMATION, FALSE, NULL))
		{
			if (GetProcessId(hDup) == TargetPID)
			{
				Ret.push_back(handle_data{ CurrentPID, i.HandleValue, i.GrantedAccess });
			}

			CloseHandle(hDup);
		}

		CloseHandle(hCurrentProc);
	}

	LOG(2, "%d handle(s) to target process found\n", (DWORD)Ret.size());

	return Ret;
}