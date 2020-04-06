#include "pch.h"

#include "Eject.h"

void EjectDll(HANDLE hTargetProc, HINSTANCE hModBase)
{
	if (NT::NtCreateThreadEx)
	{
		HANDLE hThread = nullptr;
		if (FAILED(NT::NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hTargetProc, FreeLibrary, ReCa<void*>(hModBase), NULL, 0, 0, 0, nullptr)))
		{
			return;
		}

		WaitForSingleObject(hThread, INFINITE);

		CloseHandle(hThread);
	}
}