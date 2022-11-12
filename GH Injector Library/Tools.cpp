#include "pch.h"

#include "Tools.h"

std::wstring InjectionModeToString(INJECTION_MODE mode);
std::wstring LaunchMethodToString(LAUNCH_METHOD method);
std::wstring BuildNumberToVersionString(int OSBuildNumber);

bool FileExists(const wchar_t * szFile)
{
	return (GetFileAttributesW(szFile) != INVALID_FILE_ATTRIBUTES);
}

DWORD ValidateFile(const wchar_t * szFile, DWORD desired_machine)
{
	std::ifstream File(szFile, std::ios::binary | std::ios::ate);
	if (!File.good())
	{
		LOG(1, "Can't open file\n");

		return FILE_ERR_CANT_OPEN_FILE;
	}

	auto FileSize = File.tellg();
	if (FileSize < 0x1000)
	{
		LOG(1, "Specified file is too small\n");

		return FILE_ERR_INVALID_FILE_SIZE;
	}

	BYTE * headers = new(std::nothrow) BYTE[0x1000]();
	if (headers == nullptr)
	{
		LOG(1, "Memory allocation failed\n");

		return FILE_ERR_MEMORY_ALLOCATION_FAILED;
	}

	File.seekg(0, std::ios::beg);
	File.read(ReCa<char *>(headers), 0x1000);
	File.close();

	auto * pDos = ReCa<IMAGE_DOS_HEADER *>(headers);
	WORD magic = pDos->e_magic;
	
	if (magic != IMAGE_DOS_SIGNATURE)
	{
		delete[] headers;

		LOG(1, "Invalid DOS header signature\n");

		return FILE_ERR_INVALID_FILE;
	}

	if (pDos->e_lfanew > 0x1000)
	{
		delete[] headers;

		LOG(1, "Invalid nt header offset\n");

		return FILE_ERR_INVALID_FILE;
	}

	auto * pNT = ReCa<IMAGE_NT_HEADERS *>(headers + pDos->e_lfanew); //no need for correct nt headers type
	DWORD	signature	= pNT->Signature;
	WORD	machine		= pNT->FileHeader.Machine;
	WORD	character	= pNT->FileHeader.Characteristics;

	delete[] headers;

	if (signature != IMAGE_NT_SIGNATURE || machine != desired_machine || !(character & IMAGE_FILE_DLL)) //"MZ" & "PE"
	{
		LOG(1, "Invalid PE header\n");

		return FILE_ERR_INVALID_FILE;
	}

	return FILE_ERR_SUCCESS;
}

bool GetOwnModulePathA(char * pOut, size_t BufferCchSize)
{
	DWORD mod_ret = GetModuleFileNameA(g_hInjMod, pOut, (DWORD)BufferCchSize);
	if (!mod_ret || GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		return false;
	}

	HRESULT hr = StringCchLengthA(pOut, BufferCchSize, &BufferCchSize);
	if (FAILED(hr) || !BufferCchSize)
	{
		return false;
	}

	pOut += BufferCchSize;
	while (*(--pOut - 1) != '\\');
	*pOut = '\0';

	return true;
}

bool GetOwnModulePathW(wchar_t * pOut, size_t BufferCchSize)
{
	DWORD mod_ret = GetModuleFileNameW(g_hInjMod, pOut, (DWORD)BufferCchSize);
	if (!mod_ret || GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		return false;
	}

	HRESULT hr = StringCchLengthW(pOut, BufferCchSize, &BufferCchSize);
	if (FAILED(hr) || !BufferCchSize)
	{
		return false;
	}

	pOut += BufferCchSize;
	while (*(--pOut - 1) != '\\');
	*pOut = '\0';

	return true;	
}

bool IsNativeProcess(HANDLE hTargetProc)
{
	BOOL bWOW64 = FALSE;
	IsWow64Process(hTargetProc, &bWOW64);

	return (bWOW64 == FALSE);
}

ULONG GetSessionId(HANDLE hTargetProc, NTSTATUS & ntRetOut)
{
	PROCESS_SESSION_INFORMATION psi{ 0 };
	ntRetOut = NATIVE::NtQueryInformationProcess(hTargetProc, PROCESSINFOCLASS::ProcessSessionInformation, &psi, sizeof(psi), nullptr);
	if (NT_FAIL(ntRetOut))
	{
		return (ULONG)-1;
	}

	return psi.SessionId;
}

bool IsElevatedProcess(HANDLE hTargetProc)
{
	HANDLE hToken = nullptr;
	if (!OpenProcessToken(hTargetProc, TOKEN_QUERY, &hToken))
	{
		return false;
	}

	TOKEN_ELEVATION te{ 0 };
	DWORD SizeOut = 0;
	GetTokenInformation(hToken, TokenElevation, &te, sizeof(te), &SizeOut);

	CloseHandle(hToken);
	
	return (te.TokenIsElevated != 0);
}

void ErrorLog(const ERROR_INFO & info)
{
	auto FullPath = g_RootPathW + L"GH_Inj_Log.txt";

	time_t time_raw	= time(nullptr);
	tm time_info;
	localtime_s(&time_info, &time_raw);
	wchar_t szTime[30]{ 0 };
	wcsftime(szTime, 30, L"%d-%m-%Y %H:%M:%S", &time_info);

	const wchar_t * szWinProductName	= nullptr;
	auto szWinReleaseId	= BuildNumberToVersionString(GetOSBuildVersion());
	wchar_t szWinCurrentBuild[10]{ 0 };

	StringCchPrintfW(szWinCurrentBuild, sizeof(szWinCurrentBuild) / sizeof(wchar_t), L"%d", GetOSBuildVersion());

	switch (GetOSVersion())
	{
		case g_Win7:
			szWinProductName = L"Windows 7";
			break;
			
		case g_Win8:
			szWinProductName = L"Windows 8";
			break;

		case g_Win81:
			szWinProductName = L"Windows 8.1";
			break;

		default:
			szWinProductName = L"Windows 10";
	}

	if (GetOSVersion() == g_Win10 && GetOSBuildVersion() >= g_Win11_21H2)
	{
		szWinProductName = L"Windows 11";	
	}

	wchar_t szFlags			[9]{ 0 };
	wchar_t szErrorCode		[9]{ 0 };
	wchar_t szAdvErrorCode	[9]{ 0 };
	wchar_t szHandleValue	[9]{ 0 };
	StringCchPrintfW(szFlags,			9, L"%08X", info.Flags);
	StringCchPrintfW(szErrorCode,		9, L"%08X", info.ErrorCode);
	StringCchPrintfW(szAdvErrorCode,	9, L"%08X", info.AdvErrorCode);
	StringCchPrintfW(szHandleValue,		9, L"%08X", info.HandleValue);

	std::wstringstream old_log;

	std::wifstream error_log_in(FullPath);
	if (error_log_in.good())
	{
		old_log << error_log_in.rdbuf();
		error_log_in.close();
	}
	
	std::wofstream error_log_out(FullPath, std::ios::out | std::ios::trunc);
	if (!error_log_out.good())
	{
		LOG(1, "Failed to open/create error log file:\n%ls\n", FullPath.c_str());

		return;
	}

	error_log_out << szTime																															<< std::endl;
	error_log_out << L"Version            : "	<< L"GH Injector V" << GH_INJ_VERSION																<< std::endl;

	if (szWinReleaseId.length() > 1)
	{
		error_log_out << L"OS                 : " << szWinProductName << L" " << szWinReleaseId.c_str() << L" (Build " << szWinCurrentBuild << L")" << std::endl;
	}
	else
	{
		error_log_out << L"OS                 : " << szWinProductName << L" (Build " << szWinCurrentBuild << L")" << std::endl;
	}

	error_log_out << L"File               : "	<< (info.szDllFileName ? info.szDllFileName : L"(nullptr)")										<< std::endl;
	error_log_out << L"Target             : "	<< (info.szTargetProcessExeFileName[0] ? info.szTargetProcessExeFileName : L"(undetermined)")	<< std::endl;
	error_log_out << L"Target PID         : "	<< info.TargetProcessId																			<< std::endl;
	error_log_out << L"Source             : "	<< info.szSourceFile << L" in " << info.szFunctionName << L" at line " << info.Line				<< std::endl;
	error_log_out << L"Errorcode          : 0x"	<< szErrorCode																					<< std::endl;
	error_log_out << L"Advanced errorcode : 0x"	<< szAdvErrorCode																				<< std::endl;
	error_log_out << L"Injectionmode      : "	<< InjectionModeToString(info.InjectionMode)													<< std::endl;
	error_log_out << L"Launchmethod       : "	<< LaunchMethodToString(info.LaunchMethod)														<< std::endl;
	error_log_out << L"Platform           : "	<< (info.bNative > 0 ? L"x64/x86 (native)" : (info.bNative == 0 ? L"wow64" : L"---"))			<< std::endl;
	error_log_out << L"HandleValue        : 0x"	<< szHandleValue																				<< std::endl;
	error_log_out << L"Flags              : 0x"	<< szFlags																						<< std::endl;
	error_log_out << std::endl;

	if (old_log.rdbuf()->in_avail() > 0)
	{
		error_log_out << old_log.rdbuf();
	}

	error_log_out.close();
}

std::wstring InjectionModeToString(INJECTION_MODE mode)
{
	switch (mode)
	{
		case INJECTION_MODE::IM_LoadLibraryExW:
			return std::wstring(L"LoadLibraryExW");

		case INJECTION_MODE::IM_LdrLoadDll:
			return std::wstring(L"LdrLoadDll");

		case INJECTION_MODE::IM_LdrpLoadDll:
			return std::wstring(L"LdrpLoadDll");

		case INJECTION_MODE::IM_LdrpLoadDllInternal:
			return std::wstring(L"LdrpLoadDllInternal");

		case INJECTION_MODE::IM_ManualMap:
			return std::wstring(L"ManualMap");

		default:
			break;
	}

	return std::wstring(L"bruh moment");
}

std::wstring LaunchMethodToString(LAUNCH_METHOD method)
{
	switch (method)
	{
		case LAUNCH_METHOD::LM_NtCreateThreadEx:
			return std::wstring(L"NtCreateThreadEx");

		case LAUNCH_METHOD::LM_HijackThread:
			return std::wstring(L"HijackThread");

		case LAUNCH_METHOD::LM_SetWindowsHookEx:
			return std::wstring(L"SetWindowsHookEx");

		case LAUNCH_METHOD::LM_QueueUserAPC:
			return std::wstring(L"QueueUserAPC");

		case LAUNCH_METHOD::LM_KernelCallback:
			return std::wstring(L"KernelCallback");

		case LAUNCH_METHOD::LM_FakeVEH:
			return std::wstring(L"FakeVEH");

		default:
			break;
	}

	return std::wstring(L"bruh moment");
}

std::wstring BuildNumberToVersionString(int OSBuildNumber)
{
	switch (OSBuildNumber)
	{
		case g_Win7_SP1:
		case g_Win8_SP1:
			return std::wstring(L"SP1");

		case g_Win10_1507:
			return std::wstring(L"1507");

		case g_Win10_1511:
			return std::wstring(L"1511");

		case g_Win10_1607:
			return std::wstring(L"1607");

		case g_Win10_1703:
			return std::wstring(L"1703");

		case g_Win10_1709:
			return std::wstring(L"1709");

		case g_Win10_1803:
			return std::wstring(L"1803");

		case g_Win10_1809:
			return std::wstring(L"1809");

		case g_Win10_1903:
			return std::wstring(L"1903");

		case g_Win10_1909:
			return std::wstring(L"1909");

		case g_Win10_2004:
			return std::wstring(L"2004");

		case g_Win10_20H2:
			return std::wstring(L"20H2");

		case g_Win10_21H1:
			return std::wstring(L"21H1");

		case g_Win10_21H2:
			return std::wstring(L"21H2");

		case g_Win10_22H2:
			return std::wstring(L"22H2");

		case g_Win11_21H2:
			return std::wstring(L"21H2");

		case g_Win11_22H2:
			return std::wstring(L"22H2");

		default:
			return std::wstring(L"");
	}
}

#if !defined(_WIN64) && defined(DUMP_SHELLCODE)

int section_index = 0;

void DumpShellcode(BYTE * start, int length, const wchar_t * szShellname)
{
	wchar_t Shellcodename[] = L"Shellcodes.txt";

	wchar_t FullPath[MAX_PATH]{ 0 };
	StringCbCopyW(FullPath, sizeof(FullPath), g_RootPathW.c_str());
	StringCbCatW(FullPath, sizeof(FullPath), Shellcodename);

	std::wofstream shellcodes(FullPath, std::ios_base::out | std::ios_base::app);
	if (!shellcodes.good())
	{
		LOG(2, "Failed to open/create shellcodename.txt file:\n%ls\n", FullPath);

		return;
	}

	++section_index;

	wchar_t sec_idx[3]{ 0 };
	swprintf_s(sec_idx, 3, L"%02X", section_index);

	shellcodes << "#pragma section(\"wow64_sec$" << sec_idx << "\", read, write)\n";
	shellcodes << "__declspec(allocate(\"wow64_sec$" << sec_idx << "\"))";
	shellcodes << L"inline unsigned char " << szShellname << L"[] =\n{";

	int row_length = 500;
	int char_count = 6 * length - 2 + (length / row_length + 1) * 2 + 1; 
	wchar_t * array_out = new(std::nothrow) wchar_t[char_count]();

	if (!array_out)
	{
		LOG(2, "Failed to allocate buffer for shellcode data\n");
	
		shellcodes.close();
	}

	int idx = 0;

	for (auto i = 0; i < length; ++i)
	{
		if (!(i % row_length))
		{
			array_out[idx++] = '\n';
			array_out[idx++] = '\t';
		}

		swprintf_s(&array_out[idx], char_count - idx, L"0x%02X", start[i]);

		idx += 4;

		if (i == length - 1)
		{
			break;
		}

		array_out[idx++] = ',';
		array_out[idx++] = ' ';
	}

	shellcodes << array_out;
	shellcodes << L"\n};\n\n";

	shellcodes.close();
}

#endif

float __stdcall GetDownloadProgress(bool bWow64)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	return GetDownloadProgressEx(0, bWow64);
}

float __stdcall GetDownloadProgressEx(int index, bool bWow64)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	if (index == 0)
	{
#ifdef _WIN64
		if (bWow64)
		{
			return sym_ntdll_wow64.GetDownloadProgress();
		}
		else
		{
			return sym_ntdll_native.GetDownloadProgress();
		}
#else
		UNREFERENCED_PARAMETER(bWow64);

		return sym_ntdll_native.GetDownloadProgress();
#endif
	}
	else if (index == 1)
	{
#ifdef _WIN64
		if (bWow64)
		{
			return sym_kernel32_wow64.GetDownloadProgress();
		}
		else
		{
			return sym_kernel32_native.GetDownloadProgress();
		}
#else
		UNREFERENCED_PARAMETER(bWow64);

		return sym_kernel32_native.GetDownloadProgress();
#endif
	}

	return 0.0f;
}

void __stdcall StartDownload()
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	LOG(0, "Beginning download(s)\n");

	sym_ntdll_native.SetDownload(true);

#ifdef _WIN64
	sym_ntdll_wow64.SetDownload(true);
#endif

	if (GetOSVersion() == g_Win7)
	{
		sym_kernel32_native.SetDownload(true);

#ifdef _WIN64
		sym_kernel32_wow64.SetDownload(true);
#endif
	}
}

void __stdcall InterruptDownload()
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	LOG(0, "Interupting download thread(s)\n");

	sym_ntdll_native.Interrupt();

#ifdef _WIN64
	sym_ntdll_wow64.Interrupt();
#endif

	if (GetOSVersion() == g_Win7)
	{
		sym_kernel32_native.Interrupt();

#ifdef _WIN64
		sym_kernel32_wow64.Interrupt();
#endif
	}

	SetEvent(g_hInterruptImport);

	LOG(0, "Waiting for download thread(s) to exit\n");

	while (sym_ntdll_native_ret.wait_for(std::chrono::milliseconds(50)) != std::future_status::ready);
	LOG(0, "ntdll.pdb download thread exited successfully\n");

#ifdef _WIN64
	while (sym_ntdll_native_ret.wait_for(std::chrono::milliseconds(50)) != std::future_status::ready);
	LOG(0, "wntdll.pdb download thread exited successfully\n");
#endif
	
	if (GetOSVersion() == g_Win7)
	{
		while (sym_kernel32_native_ret.wait_for(std::chrono::milliseconds(50)) != std::future_status::ready);
		LOG(0, "kernel32.pdb download thread exited successfully\n");

#ifdef _WIN64
		while (sym_kernel32_wow64_ret.wait_for(std::chrono::milliseconds(50)) != std::future_status::ready);
		LOG(0, "wkernel32.pdb download thread exited successfully\n");
#endif
	}

	while (import_handler_ret.wait_for(std::chrono::milliseconds(50)) != std::future_status::ready);
	LOG(0, "Import handler thread (native) exited successfully\n");

#ifdef _WIN64
	while (import_handler_wow64_ret.wait_for(std::chrono::milliseconds(50)) != std::future_status::ready);
	LOG(0, "Import handler thread (wow64) exited successfully\n");
#endif
}

DWORD __stdcall InterruptDownloadEx(void * pArg)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	UNREFERENCED_PARAMETER(pArg);

	InterruptDownload();

	return 0;
}

bool __stdcall InterruptInjection(DWORD Timeout)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	auto ret = WaitForSingleObject(g_hRunningEvent, 0);
	if (ret != WAIT_OBJECT_0)
	{
		LOG(0, "No injection running\n");

		return false;
	}

	if (!SetEvent(g_hInterruptEvent))
	{
		LOG(0, "Failed to set interrupt event: %08X\n", GetLastError());

		return false;
	}

	ret = WaitForSingleObject(g_hInterruptedEvent, Timeout);
	if (ret != WAIT_OBJECT_0)
	{
		if (ret == WAIT_FAILED)
		{
			LOG(0, "Interrupt failed:\n", GetLastError());
		}
		else
		{
			LOG(0, "Interrupt timed out: %08X\n", ret);
		}

		return false;
	}

	LOG(0, "Successfully interrupted injection thread\n");

	return true;
}

DWORD __stdcall InterruptInjectionEx(void * Timeout)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	return InterruptInjection(MDWD(Timeout));
}