#include "pch.h"

#include "main.h"

int main(int argc, char * argv[])
{
	if (argc < 2)
	{
		return SM_ERR_INVALID_ARGC;
	}

	if (argv[1][0] == '0')
	{
		return (int)_SetWindowsHookEx();
	}
#ifndef _WIN64
	else if (argv[1][0] == '1')
	{
		HANDLE hEventStart = reinterpret_cast<HANDLE>(strtol(argv[2], nullptr, 0x10));
		SetEvent(hEventStart);

		HANDLE hEventEnd = reinterpret_cast<HANDLE>(strtol(argv[3], nullptr, 0x10));
		WaitForSingleObject(hEventEnd, INFINITE);

		CloseHandle(hEventStart);
		CloseHandle(hEventEnd);

		return SM_ERR_SUCCESS;
	}
#endif
	
	return SM_ERR_INVALID_ARGV;
}