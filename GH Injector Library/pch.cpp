#include "pch.h"

#include "Error.h"

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "Urlmon.lib")
#pragma comment(lib, "WinInet.lib")

#if (PSAPI_VERSION == 1)
#pragma comment(lib, "Psapi.lib")
#endif

#ifdef CUSTOM_PRINT

DWORD __stdcall SetRawPrintCallback(f_raw_print_callback print)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	if (!print)
	{
		return INJ_ERR_INVALID_POINTER;
	}

	g_print_raw_callback = print;

	return INJ_ERR_SUCCESS;
}

void ImTheTrashMan(const wchar_t * expression, const wchar_t * function, const wchar_t * file, unsigned int line, uintptr_t pReserved)
{
	UNREFERENCED_PARAMETER(expression);
	UNREFERENCED_PARAMETER(function);
	UNREFERENCED_PARAMETER(file);
	UNREFERENCED_PARAMETER(line);
	UNREFERENCED_PARAMETER(pReserved);

	//take that, CRT
	//but for real, the CRT error "handlers" are the dumbest shit ever because other than some strings you get no info to actually handle the error
	//or I am too dumb
	//probably both
}

void custom_print(const char * format, ...)
{
	int result = 0;
	int size = 1024;
	char * buffer = new char[size]();

	if (!buffer)
	{
		return;
	}

	auto old = _set_thread_local_invalid_parameter_handler(ImTheTrashMan);

	do
	{
		va_list args;
		va_start(args, format);

		int err = 0;
		result = vsprintf_s(buffer, size, format, args);

		if (result <= 0)
		{
			err = errno;
		}

		va_end(args);

		if (result < 0 && err == ERANGE)
		{
			delete[] buffer;

			size += 1024;
			buffer = new char[size]();

			if (!buffer)
			{
				break;
			}
		}
	} while (result < 0);

	_set_thread_local_invalid_parameter_handler(old);

	if (result > 0)
	{
		if (g_print_raw_callback)
		{
			g_print_raw_callback(buffer);
		}
		else
		{
			puts(buffer);
		}
	}

	if (buffer)
	{
		delete[] buffer;
	}
}

#else

DWORD __stdcall SetRawPrintCallback(f_raw_print_callback print)
{
	UNREFERENCED_PARAMETER(print);

	return INJ_ERR_NOT_IMPLEMENTED;
}

#endif