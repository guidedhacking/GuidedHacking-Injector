#include "pch.h"

#include "Eject.h"

void EjectDll(HANDLE hTargetProc, HINSTANCE hModBase)
{
	HANDLE hThread = nullptr;
	if (FAILED(NATIVE::NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hTargetProc, FreeLibrary, ReCa<void*>(hModBase), NULL, 0, 0, 0, nullptr)))
	{
		return;
	}

	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
}