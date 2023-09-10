/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

#include "pch.h"

#include "Tools.h"
#include "Import Handler.h"

std::wstring InjectionModeToString(INJECTION_MODE mode);
std::wstring LaunchMethodToString(LAUNCH_METHOD method);
std::wstring BuildNumberToVersionString(int OSBuildNumber);

bool IsWin7OrGreater()
{
	return (GetOSVersion() >= g_Win7);
}

bool IsWin8OrGreater()
{
	return (GetOSVersion() >= g_Win8);
}

bool IsWin81OrGreater()
{
	return (GetOSVersion() >= g_Win81);
}

bool IsWin10OrGreater()
{
	return (GetOSVersion() >= g_Win10);
}

bool IsWin11OrGreater()
{
	return (GetOSVersion() >= g_Win10 && GetOSBuildVersion() >= g_Win11_21H2);
}

DWORD GetOSVersion(DWORD * error_code)
{
	if (g_OSVersion != 0)
	{
		return g_OSVersion;
	}

#ifdef _WIN64
	PEB * pPEB = ReCa<PEB *>(__readgsqword(0x60));
#else
	PEB * pPEB = ReCa<PEB *>(__readfsdword(0x30));
#endif

	if (!pPEB)
	{
		if (error_code)
		{
			*error_code = INJ_ERR_CANT_GET_PEB;
		}

		return 0;
	}

	DWORD v_hi = pPEB->OSMajorVersion;
	DWORD v_lo = pPEB->OSMinorVersion;

	for (; v_lo >= 10; v_lo /= 10);

	g_OSVersion = v_hi * 10 + v_lo;

	g_OSBuildNumber = pPEB->OSBuildNumber;

	return g_OSVersion;
}

DWORD GetOSBuildVersion()
{
	return g_OSBuildNumber;
}

bool FileExistsW(const std::wstring & FilePath)
{
	return (GetFileAttributesW(FilePath.c_str()) != INVALID_FILE_ATTRIBUTES);
}

DWORD ValidateDllFile(const std::wstring & FilePath, DWORD target_machine)
{
	std::ifstream File(FilePath, std::ios::binary | std::ios::ate);
	if (!File.good())
	{
		LOG(1, "Can't open file\n");

		return FILE_ERR_CANT_OPEN_FILE;
	}

	auto FileSize = File.tellg();
	if (FileSize < 0x1000)
	{
		LOG(1, "Specified file is too small\n");

		File.close();

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

	auto * dos_header = ReCa<IMAGE_DOS_HEADER *>(headers);
	
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) //"MZ"
	{
		delete[] headers;

		LOG(1, "Invalid DOS header signature\n");

		return FILE_ERR_INVALID_FILE;
	}

	if (dos_header->e_lfanew > 0x1000)
	{
		delete[] headers;

		LOG(1, "Invalid nt header offset\n");

		return FILE_ERR_INVALID_FILE;
	}

	auto nt_headers = ReCa<IMAGE_NT_HEADERS *>(headers + dos_header->e_lfanew);
	if (nt_headers->Signature != IMAGE_NT_SIGNATURE)  //"PE"
	{
		LOG(1, "Not a valid PE file (nt signature mismatch)\n");

		delete[] headers;

		return FILE_ERR_INVALID_FILE;
	}

	WORD character = nt_headers->FileHeader.Characteristics;
	if (!(character & IMAGE_FILE_DLL))
	{
		LOG(1, "Not a valid DLL (characteristics mismatch)\n");

		delete[] headers;

		return FILE_ERR_INVALID_FILE;
	}

	delete[] headers;

	if (nt_headers->FileHeader.Machine != target_machine)
	{
		LOG(1, "DLL platform mismatch\n");

		return FILE_ERR_INVALID_FILE;
	}

	return FILE_ERR_SUCCESS;
}

DWORD ValidateDllFileInMemory(const BYTE * RawData, DWORD RawSize, DWORD target_machine)
{
	if (RawSize < 0x1000)
	{
		LOG(1, "Specified file is too small\n");

		return FILE_ERR_INVALID_FILE_SIZE;
	}

	auto * dos_header = ReCa<const IMAGE_DOS_HEADER *>(RawData);

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) //"MZ"
	{
		LOG(1, "Invalid DOS header signature\n");

		return FILE_ERR_INVALID_FILE;
	}

	if (dos_header->e_lfanew > 0x1000)
	{
		LOG(1, "Invalid nt header offset\n");

		return FILE_ERR_INVALID_FILE;
	}

	auto nt_headers = ReCa<const IMAGE_NT_HEADERS *>(RawData + dos_header->e_lfanew);
	if (nt_headers->Signature != IMAGE_NT_SIGNATURE)  //"PE"
	{
		LOG(1, "Not a valid PE file (nt signature mismatch)\n");

		return FILE_ERR_INVALID_FILE;
	}

	WORD character = nt_headers->FileHeader.Characteristics;
	if (!(character & IMAGE_FILE_DLL))
	{
		LOG(1, "Not a valid DLL (characteristics mismatch)\n");

		return FILE_ERR_INVALID_FILE;
	}

	if (nt_headers->FileHeader.Machine != target_machine)
	{
		LOG(1, "DLL platform mismatch\n");

		return FILE_ERR_INVALID_FILE;
	}

	return FILE_ERR_SUCCESS;
}

bool GetOwnModulePathA(std::string & out)
{
	char buffer[MAX_PATH * 2]{ 0 };
	DWORD mod_ret = GetModuleFileNameA(g_hInjMod, buffer, sizeof(buffer));
	if (!mod_ret || GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		return false;
	}

	std::string temp = buffer;
	auto pos = temp.find_last_of('\\');
	if (pos == std::string::npos)
	{
		return false;
	}

	out = temp.substr(0, pos + 1);

	return true;
}

bool GetOwnModulePathW(std::wstring & out)
{
	wchar_t buffer[MAX_PATH * 2]{ 0 };
	DWORD mod_ret = GetModuleFileNameW(g_hInjMod, buffer, sizeof(buffer) / sizeof(wchar_t));
	if (!mod_ret || GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		return false;
	}

	std::wstring temp = buffer;
	auto pos = temp.find_last_of('\\');
	if (pos == std::string::npos)
	{
		return false;
	}

	out = temp.substr(0, pos + 1);

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
		return SESSION_ID_INVALID;
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

	std::wstring szWinCurrentBuild	= std::format(L"{:d}", GetOSBuildVersion());
	std::wstring szWinReleaseId		= BuildNumberToVersionString(GetOSBuildVersion());
	
	std::wstring WinProductName;
	switch (GetOSVersion())
	{
		case g_Win7:
			WinProductName = L"Windows 7";
			break;
			
		case g_Win8:
			WinProductName = L"Windows 8";
			break;

		case g_Win81:
			WinProductName = L"Windows 8.1";
			break;

		default:
			WinProductName = L"Windows 10";
	}

	if (GetOSVersion() == g_Win10 && GetOSBuildVersion() >= g_Win11_21H2)
	{
		WinProductName = L"Windows 11";
	}

	auto Flags			= std::format(L"{:08X}", info.Flags);
	auto ErrorCode		= std::format(L"{:08X}", info.ErrorCode);
	auto AdvErrorCode	= std::format(L"{:08X}", info.AdvErrorCode);
	auto HandleValue	= std::format(L"{:08X}", info.HandleValue);

	auto RawSize = std::format(L"{:08X}", info.RawSize);
#ifdef _WIN64
	auto RawData = std::format(L"{:016X}", ReCa<ULONG_PTR>(info.RawData));
#else
	auto RawData = std::format(L"{:08X}", ReCa<ULONG_PTR>(info.RawData));
#endif

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
		error_log_out << L"OS                 : " << WinProductName << L" " << szWinReleaseId << L" (Build " << szWinCurrentBuild << L")" << std::endl;
	}
	else
	{
		error_log_out << L"OS                 : " << WinProductName << L" (Build " << szWinCurrentBuild << L")" << std::endl;
	}
	
	if (info.RawData)
	{
		error_log_out << L"RawData            : 0x" << RawData << std::endl;
		error_log_out << L"RawSize            : 0x" << RawSize << L" bytes" << std::endl;
	}
	else
	{
		error_log_out << L"File               : " << info.DllFileName.c_str() << std::endl;
	}

	error_log_out << L"Target             : "	<< info.TargetProcessExeFileName.c_str()												<< std::endl;
	error_log_out << L"Target PID         : "	<< info.TargetProcessId																	<< std::endl;
	error_log_out << L"Source             : "	<< info.SourceFile << L" in " << info.FunctionName << L" at line " << info.Line			<< std::endl;
	error_log_out << L"Errorcode          : 0x"	<< ErrorCode																			<< std::endl;
	error_log_out << L"Advanced errorcode : 0x"	<< AdvErrorCode																			<< std::endl;
	error_log_out << L"Injectionmode      : "	<< InjectionModeToString(info.InjectionMode)											<< std::endl;
	error_log_out << L"Launchmethod       : "	<< LaunchMethodToString(info.LaunchMethod)												<< std::endl;
	error_log_out << L"Platform           : "	<< (info.bNative > 0 ? L"x64/x86 (native)" : (info.bNative == 0 ? L"wow64" : L"---"))	<< std::endl;
	error_log_out << L"HandleValue        : 0x"	<< HandleValue																			<< std::endl;
	error_log_out << L"Flags              : 0x"	<< Flags																				<< std::endl;

	if (info.IsDotNet)
	{
		error_log_out << L".NET Version       : " << info.Version	<< std::endl;
		error_log_out << L"Namespace          : " << info.Namespace << std::endl;
		error_log_out << L"Classname          : " << info.ClassName << std::endl;
		error_log_out << L"Method             : " << info.Method	<< std::endl;
		error_log_out << L"Argument           : " << info.Argument	<< std::endl;
	}

	error_log_out << std::endl;

	if (old_log.rdbuf()->in_avail() > 0)
	{
		error_log_out << old_log.rdbuf();
	}

	error_log_out.close();
}

std::wstring CharArrayToStdWstring(const char * szString)
{
	if (!szString)
	{
		return std::wstring();
	}

	std::string s(szString);
	std::vector<char> v(s.begin(), s.end());
	return std::wstring(v.begin(), v.end());
}

bool StdWStringToWCharArray(const std::wstring & Source, wchar_t * szBuffer, size_t Size)
{
	if (!szBuffer)
	{
		return false;
	}

	auto len = Source.length();
	if (len >= Size)
	{
		return false;
	}

	Source.copy(szBuffer, len);
	szBuffer[len + 1] = '\0';

	return true;
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
	auto FullPath = g_RootPathW;
	FullPath += L"Shellcodes.txt";

	std::wofstream shellcodes(FullPath, std::ios_base::out | std::ios_base::app);
	if (!shellcodes.good())
	{
		LOG(2, "Failed to open/create Shellcodes.txt:\n%ls\n", FullPath.c_str());

		return;
	}

	++section_index;

	wchar_t sec_idx[3]{ 0 };
	swprintf_s(sec_idx, 3, L"%02X", section_index);

	shellcodes << "#pragma section(\"wow64_sec$" << sec_idx << "\", read, write)\n";
	shellcodes << "__declspec(allocate(\"wow64_sec$" << sec_idx << "\"))";
	shellcodes << L" inline unsigned char " << szShellname << L"[] =\n{";

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

	if (index == PDB_DOWNLOAD_INDEX_NTDLL)
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
	else if (index == PDB_DOWNLOAD_INDEX_KERNEL32 && GetOSVersion() == g_Win7)
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

DWORD CreateTempFileCopy(std::wstring & FilePath, DWORD & win32err)
{
	auto FileNamePos = FilePath.find_last_of('\\');
	if (FileNamePos == std::wstring::npos)
	{
		return INJ_ERR_INVALID_FILEPATH;
	}

	auto FileName = std::wstring(FilePath.substr(FileNamePos + 1));
	
	wchar_t szTempPath[MAXPATH_IN_TCHAR]{ 0 };
	if (!GetTempPathW(sizeof(szTempPath) / sizeof(wchar_t), szTempPath))
	{
		win32err = GetLastError();

		return INJ_ERR_CANT_GET_TEMP_DIR;
	}

	std::wstring TempPath = szTempPath;
	TempPath += FileName;

	if (!CopyFileW(FilePath.c_str(), TempPath.c_str(), FALSE))
	{
		win32err = GetLastError();

		return INJ_ERR_CANT_COPY_FILE;
	}

	FilePath = TempPath;

	return FILE_ERR_SUCCESS;
}

DWORD ScrambleFileName(std::wstring & FilePath, UINT Length, DWORD & win32err)
{
	auto FileNamePos = FilePath.find_last_of('\\');
	if (FileNamePos == std::wstring::npos)
	{
		return INJ_ERR_INVALID_FILEPATH;
	}

	auto NewPath = std::wstring(FilePath.substr(0, FileNamePos + 1));
	
	int seed = rand() + (int)(MDWD(&NewPath) & 0x7FFFFFFF); //epic rng
	LARGE_INTEGER pfc{ 0 };
	QueryPerformanceCounter(&pfc);
	seed += pfc.LowPart;
	srand(seed);

	for (UINT i = 0; i != Length; ++i)
	{
		auto val = rand() % 3;
		if (val == 0)
		{
			val = rand() % 10;
			NewPath += wchar_t('0' + val);
		}
		else if (val == 1)
		{
			val = rand() % 26;
			NewPath += wchar_t('A' + val);
		}
		else
		{
			val = rand() % 26;
			NewPath += wchar_t('a' + val);
		}
	}
	NewPath += L".dll";

	auto ren_ret = _wrename(FilePath.c_str(), NewPath.c_str());
	if (ren_ret)
	{
		win32err = (DWORD)errno;

		return INJ_ERR_CANT_RENAME_FILE;
	}

	FilePath = NewPath;

	return FILE_ERR_SUCCESS;
}