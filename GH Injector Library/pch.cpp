#include "pch.h"

#include "Error.h"

#pragma comment (lib, "DbgHelp.lib")
#pragma comment (lib, "Shlwapi.lib")
#pragma comment (lib, "Urlmon.lib")
#pragma comment (lib, "Version.lib")
#pragma comment (lib, "WinInet.lib")
#pragma comment (lib, "wtsapi32.lib")

#if (PSAPI_VERSION == 1)
#pragma comment(lib, "Psapi.lib")
#endif

#ifdef DEBUG_INFO

DWORD __stdcall SetRawPrintCallback(f_raw_print_callback print)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	if (!print)
	{
		g_print_raw_callback = nullptr;

		LOG(0, "Removed print callback\n");

		return INJ_ERR_INVALID_POINTER;
	}

	g_print_raw_callback = print;

	LOG(0, "Set print callback: %p\n", g_print_raw_callback);

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

void custom_print(int indention_offset, const char * format, ...)
{
	size_t size = 1024;
	char * buffer = new(std::nothrow) char[size + indention_offset]();

	if (!buffer)
	{
		return;
	}

	memset(buffer, '\x20', indention_offset);

	auto old = _set_thread_local_invalid_parameter_handler(ImTheTrashMan);

	int result = 0;

	do
	{
		va_list args;
		va_start(args, format);

		int err = 0;
		result = vsprintf_s(buffer + indention_offset, size, format, args);

		if (result <= 0)
		{
			err = errno;
		}

		va_end(args);

		if (result < 0 && err == ERANGE)
		{
			delete[] buffer;

			size += 1024;
			buffer = new(std::nothrow) char[size + indention_offset]();

			if (!buffer)
			{
				break;
			}

			memset(buffer, '\x20', indention_offset);
		}
		else if (result < 0)
		{
			break;
		}
	} while (result < 0);

	_set_thread_local_invalid_parameter_handler(old);

	if (result > 0)
	{

#ifdef CUSTOM_PRINT
		if (g_print_raw_callback)
		{
			g_print_raw_callback(buffer);
		}
		else
		{
			auto len = strlen(buffer);

			if (len > 0)
			{
				if (buffer[len - 1] == '\n')
				{
					buffer[len - 1] = '\0';
				}

				puts(buffer);
			}
		}
#else
		auto len = strlen(buffer);

		if (len > 0)
		{
			if (buffer[len - 1] == '\n')
			{
				buffer[len - 1] = '\0';
			}

			puts(buffer);
		}
#endif

	}

	if (buffer)
	{
		delete[] buffer;
	}
}

#else

DWORD __stdcall SetRawPrintCallback(f_raw_print_callback print)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	UNREFERENCED_PARAMETER(print);

	return INJ_ERR_NOT_IMPLEMENTED;
}

#endif