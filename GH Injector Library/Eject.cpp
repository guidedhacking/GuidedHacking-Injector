#include "pch.h"

#include "Eject.h"

//gonna make this better eventually, forgot it existed

void EjectDll(HANDLE hTargetProc, HINSTANCE hModBase)
{
	LOG("Ejecting injection library from hijack process\n");

	HANDLE hThread = nullptr;
	if (FAILED(NATIVE::NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hTargetProc, FreeLibrary, ReCa<void*>(hModBase), NULL, 0, 0, 0, nullptr)))
	{
		LOG("Failed to eject library\n");

		return;
	}

	WaitForSingleObject(hThread, 500);

	CloseHandle(hThread);

	LOG("Library ejected\n");
}