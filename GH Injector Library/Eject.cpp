#include "pch.h"

#include "Eject.h"

bool EjectDll(HANDLE hTargetProc, HINSTANCE hModule)
{
	LOG("    EjectDll called\n");
	LOG("     PID     = %08X\n", GetProcessId(hTargetProc));
	LOG("     hModule = %p\n", hModule);

	HANDLE hThread = nullptr;
	auto ntRet = NATIVE::NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hTargetProc, NATIVE::LdrUnloadDll, ReCa<void *>(hModule), NULL, 0, 0, 0, nullptr);
	if (FAILED(ntRet))
	{
		LOG("    NtCreateThreadEx failed: %08X\n", ntRet);

		return false;
	}

	if (WaitForSingleObject(hThread, 500) != WAIT_OBJECT_0)
	{
		LOG("    Ejection thread timed out\n");

		TerminateThread(hThread, 0);
		CloseHandle(hThread);

		return false;
	}

	if (!GetExitCodeThread(hThread, ReCa<DWORD *>(&ntRet)))
	{
		LOG("    GetExitCodeThread failed: %08X\n", GetLastError());
	
		CloseHandle(hThread);

		return false;
	}

	CloseHandle(hThread);

	if (NT_FAIL(ntRet))
	{
		LOG("    LdrUnloadDll failed: %08X\n", ntRet);

		return false;
	}

	LOG("    Dll ejected successfully\n");

	return true;
}