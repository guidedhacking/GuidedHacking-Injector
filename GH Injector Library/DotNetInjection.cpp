/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

#include "pch.h"

#include "DotNetInjection.h"

DWORD ValidateDotNetDllFile(const std::wstring & FilePath, DWORD target_machine, std::wstring & version_out);

DWORD DotNet_InitErrorStruct(const DOTNET_INJECTIONDATA_INTERNAL & Data, int Native, DWORD ErrorCode, const ERROR_DATA & error_data);

DWORD __stdcall DotNet_InjectA(DOTNET_INJECTIONDATAA * pData)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	LOG(0, "DotNet_InjectA called with pData = %p\n", pData);
	
	if (WaitForSingleObject(g_hRunningEvent, 0) == WAIT_OBJECT_0)
	{
		LOG(0, "Different injection in progress. Wait for the other injection to finish first.\n");

		return INJ_ERR_ALREADY_RUNNING;
	}

	if (!pData)
	{
		LOG(0, "pData is invalid\n");

		return INJ_ERR_NO_DATA;
	}

	ERROR_DATA error_data{ 0 };

	if (!pData->szDllPath)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Invalid path\n");

		return INJ_ERR_INVALID_FILEPATH;
	}
	
	DOTNET_INJECTIONDATA_INTERNAL data_internal(pData);
	DWORD Ret = DotNet_Inject_Internal(&data_internal);
	pData->hDllOut = data_internal.hDllOut;

	return Ret;
}

DWORD __stdcall DotNet_InjectW(DOTNET_INJECTIONDATAW * pData)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	LOG(0, "DotNet_InjectW called with pData = %p\n", pData);
	
	if (WaitForSingleObject(g_hRunningEvent, 0) == WAIT_OBJECT_0)
	{
		LOG(0, "Different injection in progress. Wait for the other injection to finish first.\n");

		return INJ_ERR_ALREADY_RUNNING;
	}

	if (!pData)
	{
		LOG(0, "pData is invalid\n");

		return INJ_ERR_NO_DATA;
	}

	ERROR_DATA error_data{ 0 };

	if (!pData->szDllPath)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Invalid path\n");

		return INJ_ERR_INVALID_FILEPATH;
	}
	
	DOTNET_INJECTIONDATA_INTERNAL data_internal(pData);
	DWORD Ret = DotNet_Inject_Internal(&data_internal);
	pData->hDllOut = data_internal.hDllOut;

	return Ret;
}

DWORD __stdcall DotNet_Inject_Internal(DOTNET_INJECTIONDATA_INTERNAL * pData)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	SetEvent(g_hRunningEvent);
	ResetEvent(g_hInterruptEvent);
	ResetEvent(g_hInterruptedEvent);

	DWORD RetVal = INJ_ERR_SUCCESS;

	ERROR_DATA error_data{ 0 };
	auto & Data = *pData;

	RetVal = GetImportState();
	if (RetVal != INJ_ERR_SUCCESS)
	{
		LOG(0, "Resolving imports failed: %08X\n", RetVal);

		error_data = import_handler_error_data;

		return DotNet_InitErrorStruct(Data, -1, INJ_ERR_IMPORT_HANDLER_NOT_DONE, error_data);
	}

	if (Data.Mode == INJECTION_MODE::IM_LdrpLoadDllInternal && !IsWin10OrGreater())
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "LdrpLoadDllInternal is only supported on Windows 10\n");

		return DotNet_InitErrorStruct(Data, -1, INJ_ERR_NOT_SUPPORTED, error_data);
	}

	if (Data.DllPath.empty())
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Invalid path provided (empty string)\n");

		return DotNet_InitErrorStruct(Data, -1, INJ_ERR_INVALID_FILEPATH, error_data);
	}

	if (!FileExistsW(Data.DllPath))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(0, "File doesn't exist: %08X\n", error_data.AdvErrorCode);

		return DotNet_InitErrorStruct(Data, -1, INJ_ERR_FILE_DOESNT_EXIST, error_data);
	}

	if (PathIsRelativeW(Data.DllPath.c_str()))
	{
		wchar_t buffer[MAX_PATH * 2]{ 0 };
		auto win_ret = GetFullPathNameW(Data.DllPath.c_str(), sizeof(buffer) / sizeof(wchar_t), buffer, nullptr);
		if (!win_ret || win_ret >= sizeof(buffer) / sizeof(wchar_t))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(0, "Failed to resolve absolute file path: %08X\n", error_data.AdvErrorCode);

			return DotNet_InitErrorStruct(Data, -1, INJ_ERR_FAILED_TO_RESOLVE_PATH, error_data);
		}

		Data.DllPath = buffer;
	}

	if (!Data.ProcessID)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Invalid process identifier specified\n");

		return DotNet_InitErrorStruct(Data, -1, INJ_ERR_INVALID_PID, error_data);
	}

	if (Data.Flags & INJ_LOAD_DLL_COPY)
	{
		LOG(0, "Copying dll into temp directory\n");

		DWORD win32err = NULL;

		auto dwRet = CreateTempFileCopy(Data.DllPath, win32err);
		if (dwRet != FILE_ERR_SUCCESS)
		{
			INIT_ERROR_DATA(error_data, win32err);

			LOG(0, "Failed to copy file to temp directory: %08X\n", dwRet);

			return DotNet_InitErrorStruct(Data, -1, dwRet, error_data);
		}

		LOG(0, "Path of dll copy: %ls\n", Data.DllPath.c_str());
	}

	if (Data.Flags & INJ_SCRAMBLE_DLL_NAME)
	{
		LOG(0, "Scrambling dll name\n");

		DWORD win32err = NULL;

		auto dwRet = ScrambleFileName(Data.DllPath, 10, win32err);
		if (dwRet != FILE_ERR_SUCCESS)
		{
			INIT_ERROR_DATA(error_data, win32err);

			LOG(0, "Failed to copy file to temp directory: %08X\n", dwRet);

			return DotNet_InitErrorStruct(Data, -1, dwRet, error_data);
		}

		LOG(0, "Path of renamed dll: %ls\n", Data.DllPath.c_str());
	}

	HANDLE hTargetProc = nullptr;
	hTargetProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Data.ProcessID);
	if (!hTargetProc)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(0, "OpenProcess failed: %08X\n", (DWORD)error_data.AdvErrorCode);

		return DotNet_InitErrorStruct(Data, -1, INJ_ERR_CANT_OPEN_PROCESS, error_data);
	}

	DWORD handle_info = 0;
	if (!hTargetProc || !GetHandleInformation(hTargetProc, &handle_info))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(0, "Invalid process handle: %08X\n", (DWORD)error_data.AdvErrorCode);

		CloseHandle(hTargetProc);

		return DotNet_InitErrorStruct(Data, -1, INJ_ERR_INVALID_PROC_HANDLE, error_data);
	}

	LOG(0, "Attached to target process\n");

	wchar_t szExePath[MAX_PATH * 2]{ 0 };
	DWORD size_inout = sizeof(szExePath) / sizeof(szExePath[0]);
	if (!QueryFullProcessImageNameW(hTargetProc, NULL, szExePath, &size_inout))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(0, "QueryFullProcessImageNameW failed: %08X\n", (DWORD)error_data.AdvErrorCode);

		CloseHandle(hTargetProc);

		return DotNet_InitErrorStruct(Data, -1, INJ_ERR_CANT_GET_EXE_FILENAME, error_data);
	}

	auto ExePath	= std::wstring(szExePath);
	auto ExeNamePos	= ExePath.find_last_of('\\');

	if (ExeNamePos == std::string::npos)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Failed to extract exe name from path\n");

		CloseHandle(hTargetProc);

		return DotNet_InitErrorStruct(Data, -1, INJ_ERR_INVALID_EXE_PATH, error_data);
	}

	Data.TargetProcessExeFileName = ExePath.substr(ExeNamePos + 1);

	LOG(0, "Target process name = %ls\n", Data.TargetProcessExeFileName.c_str());

	LOG(0, "Validating specified file\n");

	DWORD FileErr = FILE_ERR_SUCCESS;
	std::wstring dot_net_version;
	bool native_target = true;
#ifdef _WIN64
	native_target = IsNativeProcess(hTargetProc);
	if (native_target)
	{
		FileErr = ValidateDotNetDllFile(Data.DllPath, IMAGE_FILE_MACHINE_AMD64, dot_net_version);
	}
	else
	{
		FileErr = ValidateDotNetDllFile(Data.DllPath, IMAGE_FILE_MACHINE_I386, dot_net_version);
	}
#else
	FileErr = ValidateDotNetDllFile(Data.DllPath, IMAGE_FILE_MACHINE_I386, dot_net_version);
#endif

	CloseHandle(hTargetProc);

	if (FileErr != FILE_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, FileErr);

		LOG(0, "Invalid file specified\n");

		return DotNet_InitErrorStruct(Data, native_target, INJ_ERR_PLATFORM_MISMATCH, error_data);
	}

	LOG(0, "File validated and prepared for injection:\n %ls\n", Data.DllPath.c_str());
	
	std::wstring dnpPath = g_RootPathW;
#ifdef _WIN64
	if (native_target)
	{
		dnpPath += DNP_DLL_FILENAME64;
	}
	else
	{
		dnpPath += DNP_DLL_FILENAME86;
	}
#else
	dnpPath += DNP_DLL_FILENAME;
#endif

	if (!FileExistsW(dnpPath))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "DNP remote loader DLL is missing: %ls\n", dnpPath.c_str());

		return DotNet_InitErrorStruct(Data, native_target, DNP_ERR_REMOTE_LOADER_MISSING, error_data);
	}

	std::wstring InfoPath = g_RootPathW + DNP_INFO_FILENAME;
	if (FileExistsW(InfoPath))
	{
		DeleteFileW(InfoPath.c_str());
	}

	std::wofstream dnp_info(InfoPath, std::ios_base::out | std::ios_base::app);
	if (!dnp_info.good())
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Failed to create info file\n");

		return DotNet_InitErrorStruct(Data, native_target, DNP_ERR_CANT_OPEN_INFO_TXT, error_data);
	}

	dnp_info << Data.DllPath	<< std::endl;
	dnp_info << dot_net_version << std::endl;
	dnp_info << Data.Namespace	<< std::endl;
	dnp_info << Data.ClassName	<< std::endl;
	dnp_info << Data.MethodName << std::endl;
	dnp_info << Data.Argument	<< std::endl;

	auto original_info_size = dnp_info.tellp();

	dnp_info.close();

	DWORD flags_stripped = Data.Flags;

	if (flags_stripped & INJ_LOAD_DLL_COPY)
	{
		flags_stripped ^= INJ_LOAD_DLL_COPY;
	}

	if (flags_stripped & INJ_SCRAMBLE_DLL_NAME)
	{
		flags_stripped ^= INJ_SCRAMBLE_DLL_NAME;
	}
	
	if (flags_stripped & INJ_UNLINK_FROM_PEB)
	{
		flags_stripped ^= INJ_UNLINK_FROM_PEB;
	}

	if (flags_stripped & INJ_FAKE_HEADER)
	{
		flags_stripped ^= INJ_FAKE_HEADER;
	}

	if (flags_stripped & INJ_ERASE_HEADER)
	{
		flags_stripped ^= INJ_ERASE_HEADER;
	}

	INJECTIONDATA_INTERNAL loader_injection;
	loader_injection.DllPath			= dnpPath;
	loader_injection.ProcessID			= Data.ProcessID;
	loader_injection.Mode				= INJECTION_MODE::IM_LdrpLoadDll; //can't be mapped anyway
	loader_injection.Method				= Data.Method;
	loader_injection.Flags				= flags_stripped; //can't be rename scrambled/copied
	loader_injection.Timeout			= Data.Timeout;
	loader_injection.hHandleValue		= NULL;
	loader_injection.GenerateErrorLog	= Data.GenerateErrorLog;

	auto DNP_Error = Inject_Internal(&loader_injection);
	if (DNP_Error != INJ_ERR_SUCCESS || !loader_injection.hDllOut)
	{
		INIT_ERROR_DATA(error_data, DNP_Error);

		LOG(0, "Failed to load .NET loader into target process\n");

		DeleteFileW(InfoPath.c_str());

		return DotNet_InitErrorStruct(Data, native_target, DNP_ERR_CANT_OPEN_INFO_TXT, error_data);
	}

	bool dnp_info_updated = false;
	auto Timer = GetTickCount64();
	while (GetTickCount64() - Timer < Data.Timeout)
	{
		auto dwWaitRet = WaitForSingleObject(g_hInterruptEvent, 10);

		std::wifstream FileOut(InfoPath);
		if (FileOut.good())
		{
			FileOut.seekg(std::ios::end);
			auto current_info_size = FileOut.tellg();

			if (current_info_size != original_info_size)
			{
				LOG(0, ".NET loader data updated\n");

				dnp_info_updated = true;

				break;
			}
		}
		
		if (dwWaitRet == WAIT_OBJECT_0)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(0, "Interrupt!\n");

			SetEvent(g_hInterruptedEvent);

			return DNP_ERR_INTERRUPT;
		}
	}

	if (!(loader_injection.Flags & INJ_HIJACK_HANDLE))
	{
		hTargetProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, loader_injection.ProcessID);
		if (hTargetProc != NULL)
		{
			ProcessInfo pi;
			pi.SetProcess(hTargetProc);
			auto entry = pi.GetLdrEntry(loader_injection.hDllOut);
			printf("ldr entry = %p\n", entry);

			LDR_DATA_TABLE_ENTRY ldr{};
			ReadProcessMemory(hTargetProc, entry, &ldr, sizeof(ldr), nullptr);
			printf("LDR::LoadFlags : %d\n", ldr.DependentLoadFlags);
			printf("LDR::LoadReason: %d\n", ldr.LoadReason);
			printf("LDR::Flags     : %d\n", ldr.Flags);
			printf("LDR::RefCount  : %d\n", ldr.ReferenceCount);

			LDR_DDAG_NODE ddag{};
			ReadProcessMemory(hTargetProc, ldr.DdagNode, &ddag, sizeof(ddag), nullptr);
			printf("DDAG::LoadCount : %d\n", ddag.LoadCount);
			printf("DDAG::State     : %d\n", ddag.State);
			printf("DDAG::LowestLink: %d\n", ddag.LowestLink);
			printf("DDAG::Preorder  : %d\n", ddag.PreorderNumber);


			EjectDll(hTargetProc, loader_injection.hDllOut, native_target ? false : true);

			


			CloseHandle(hTargetProc);
		}
	}

	if (!dnp_info_updated)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, ".NET loader timed out\n");

		return DotNet_InitErrorStruct(Data, native_target, DNP_ERR_CANT_OPEN_INFO_TXT, error_data);
	}

	std::wifstream FileOut(InfoPath);
	if (!FileOut.good())
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, ".NET loader timed out\n");

		return DotNet_InitErrorStruct(Data, native_target, DNP_ERR_CANT_OPEN_INFO_TXT, error_data);
	}

	std::wstringstream info_raw;
	info_raw << FileOut.rdbuf();

	FileOut.close();

	DeleteFileW(InfoPath.c_str());

	std::wstring info = info_raw.str();
	std::vector<std::wstring> returned_data;

	size_t current_position = info.find('\n');
	while (current_position != std::wstring::npos)
	{
		returned_data.push_back(info.substr(0, current_position));
		info.erase(0, current_position + sizeof('\n'));

		current_position = info.find('\n');
	}

	returned_data.push_back(info);

	if (returned_data.size() < 2)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "The .NET loader returned invalid information\n");

		return DotNet_InitErrorStruct(Data, native_target, DNP_ERR_INVALID_DATA, error_data);
	}

	HINSTANCE base	= ReCa<HINSTANCE>(wcstoll(returned_data[0].c_str(), nullptr, 0x10));
	DWORD error		= wcstol(returned_data[1].c_str(), nullptr, 0x10);

	if (error != DNP_ERR_SUCCESS)
	{
		if (error == DNP_ERR_HRESULT)
		{
			INIT_ERROR_DATA(error_data, MDWD(base));

			LOG(0, "The .NET loader returned an HRESULT error code: %08X\n", MDWD(base));

			return DotNet_InitErrorStruct(Data, native_target, error, error_data);
		}

		INIT_ERROR_DATA(error_data, error);

		LOG(0, "The .NET loader returned an error code: %08X\n", error);

		return DotNet_InitErrorStruct(Data, native_target, DNP_ERR_LOADER_FAILED, error_data);
	}

	Data.hDllOut = base;

	return DNP_ERR_SUCCESS;
}

DWORD DotNet_InitErrorStruct(const DOTNET_INJECTIONDATA_INTERNAL & Data, int Native, DWORD ErrorCode, const ERROR_DATA & error_data)
{
	ResetEvent(g_hRunningEvent);

	if (!ErrorCode)
	{
		return INJ_ERR_SUCCESS;
	}

	if (Data.GenerateErrorLog)
	{
		ERROR_INFO info{ };
		info.DllFileName				= Data.DllPath;
		info.TargetProcessExeFileName	= Data.TargetProcessExeFileName;
		info.TargetProcessId			= Data.ProcessID;
		info.InjectionMode				= Data.Mode;
		info.LaunchMethod				= Data.Method;
		info.Flags						= Data.Flags;
		info.HandleValue				= Data.hHandleValue;
		info.bNative					= Native;
		
		info.ErrorCode		= ErrorCode;
		info.AdvErrorCode	= error_data.AdvErrorCode;
		info.SourceFile		= error_data.szFileName;
		info.FunctionName	= error_data.szFunctionName;
		info.Line			= error_data.Line;

		info.IsDotNet	= true;
		info.Namespace	= Data.Namespace;
		info.ClassName	= Data.ClassName;
		info.Method		= Data.MethodName;
		info.Argument	= Data.Argument;
		info.Version	= Data.Version;

		ErrorLog(info);
	}

	return ErrorCode;
}

DWORD ValidateDotNetDllFile(const std::wstring & FilePath, DWORD target_machine, std::wstring & version_out)
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

	BYTE * raw_data = new(std::nothrow) BYTE[static_cast<size_t>(FileSize)]();
	if (!raw_data)
	{
		LOG(1, "Memory allocation failed\n");

		File.close();

		return FILE_ERR_MEMORY_ALLOCATION_FAILED;
	}

	File.seekg(0, std::ios::beg);
	File.read(ReCa<char *>(raw_data), FileSize);
	File.close();

	auto dos_header = ReCa<IMAGE_DOS_HEADER *>(raw_data);
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		LOG(1, "Invalid DOS header signature\n");

		delete[] raw_data;

		return FILE_ERR_INVALID_FILE;
	}

	if (dos_header->e_lfanew > 0x1000)
	{
		delete[] raw_data;

		LOG(1, "Invalid nt header offset\n");

		return FILE_ERR_INVALID_FILE;
	}

	auto nt_headers = ReCa<IMAGE_NT_HEADERS64 *>(raw_data + dos_header->e_lfanew);
	if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
	{
		LOG(1, "Not a valid PE file (nt signature mismatch)\n");

		delete[] raw_data;

		return FILE_ERR_INVALID_FILE;
	}

	WORD character = nt_headers->FileHeader.Characteristics;	
	if (!(character & IMAGE_FILE_DLL))
	{
		LOG(1, "Not a valid DLL (characteristics mismatch)\n");

		delete[] raw_data;

		return false;
	}

	DWORD ComDirSize	= 0;
	DWORD SizeOfImage	= 0;
	DWORD SizeOfHeaders = 0;

	auto * nt64 = ReCa<IMAGE_NT_HEADERS64 *>(nt_headers);
	auto * nt32 = ReCa<IMAGE_NT_HEADERS32 *>(nt_headers);

	WORD machine = nt_headers->FileHeader.Machine;
	switch (machine)
	{
		case IMAGE_FILE_MACHINE_AMD64:
			ComDirSize		= nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size;
			SizeOfImage		= nt64->OptionalHeader.SizeOfImage;
			SizeOfHeaders	= nt64->OptionalHeader.SizeOfHeaders;
			break;

		case IMAGE_FILE_MACHINE_I386:
			ComDirSize		= nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size;
			SizeOfImage		= nt32->OptionalHeader.SizeOfImage;
			SizeOfHeaders	= nt32->OptionalHeader.SizeOfHeaders;
			break;
		
		default:
			LOG(1, "Invalid DLL platform\n");

			return FILE_ERR_INVALID_FILE;
			break;
	}

	if (machine != target_machine && target_machine != IMAGE_FILE_MACHINE_AMD64)
	{
		LOG(1, "Invalid DLL platform\n");

		delete[] raw_data;

		return FILE_ERR_INVALID_FILE;
	}

	if (!ComDirSize || !SizeOfImage || !SizeOfHeaders)
	{
		LOG(1, "DLL doesn't have a com directory or is not a managed binary\n");

		delete[] raw_data;

		return FILE_ERR_INVALID_FILE;
	}

	BYTE * mapped_image = new(std::nothrow) BYTE[SizeOfImage]();
	if (!mapped_image)
	{
		LOG(1, "Memory allocation for file mapping failed\n");

		delete[] raw_data;

		return FILE_ERR_MEMORY_ALLOCATION_FAILED;
	}

	memmove(mapped_image, raw_data, SizeOfHeaders);
	auto * pCurrentSectionHeader = IMAGE_FIRST_SECTION(nt_headers);
	for (UINT i = 0; i != nt_headers->FileHeader.NumberOfSections; ++i, ++pCurrentSectionHeader)
	{
		if (pCurrentSectionHeader->SizeOfRawData)
		{
			memmove(mapped_image + pCurrentSectionHeader->VirtualAddress, raw_data + pCurrentSectionHeader->PointerToRawData, pCurrentSectionHeader->SizeOfRawData);
		}
	}

	delete[] raw_data;

	dos_header = ReCa<IMAGE_DOS_HEADER *>(mapped_image);
	nt32 = ReCa<IMAGE_NT_HEADERS32 *>(mapped_image + dos_header->e_lfanew);
	nt64 = ReCa<IMAGE_NT_HEADERS64 *>(mapped_image + dos_header->e_lfanew);

	IMAGE_COR20_HEADER * cor20_header = nullptr;

	if (machine == IMAGE_FILE_MACHINE_AMD64)
	{
		cor20_header = ReCa<IMAGE_COR20_HEADER *>(mapped_image + nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress);
	}
	else
	{
		cor20_header = ReCa<IMAGE_COR20_HEADER *>(mapped_image + nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress);
	}

	if (!cor20_header->MetaData.Size || !cor20_header->MetaData.VirtualAddress)
	{
		LOG(1, "DLL doesn't have .NET meta data or is not a managed binary\n");

		delete[] mapped_image;

		return FILE_ERR_INVALID_FILE;
	}

	auto * meta_data = ReCa<DOTNET_META_DATA *>(mapped_image + cor20_header->MetaData.VirtualAddress);
	if (meta_data->Signature != DOT_NET_SIGNATURE)
	{
		LOG(1, "Invalid .NET signature in meta data\n");

		delete[] mapped_image;

		return FILE_ERR_INVALID_FILE;
	}

	version_out = std::wstring(meta_data->Version, meta_data->Version + meta_data->VersionStringLength);
	
	version_out.erase(
		std::remove_if(version_out.begin(), version_out.end(),
			[](wchar_t c)
			{ 
				return (c == 0); 
			}),
		version_out.end()
	);

	delete[] mapped_image;

	return FILE_ERR_SUCCESS;
}

DOTNET_INJECTIONDATA_INTERNAL::DOTNET_INJECTIONDATA_INTERNAL(const DOTNET_INJECTIONDATAA * pData)
{
	DllPath				= CharArrayToStdWstring(pData->szDllPath);
	ProcessID			= pData->ProcessID;
	Mode				= pData->Mode;
	Method				= pData->Method;
	Flags				= pData->Flags;
	Timeout				= pData->Timeout;
	hHandleValue		= pData->hHandleValue;
	GenerateErrorLog	= pData->GenerateErrorLog;

	Namespace	= CharArrayToStdWstring(pData->szNamespace);
	ClassName	= CharArrayToStdWstring(pData->szClassName);
	MethodName	= CharArrayToStdWstring(pData->szMethodName);
	Argument	= CharArrayToStdWstring(pData->szArgument);
}

DOTNET_INJECTIONDATA_INTERNAL::DOTNET_INJECTIONDATA_INTERNAL(const DOTNET_INJECTIONDATAW * pData)
{
	DllPath				= std::wstring(pData->szDllPath);
	ProcessID			= pData->ProcessID;
	Mode				= pData->Mode;
	Method				= pData->Method;
	Flags				= pData->Flags;
	Timeout				= pData->Timeout;
	hHandleValue		= pData->hHandleValue;
	GenerateErrorLog	= pData->GenerateErrorLog;

	Namespace	= std::wstring(pData->szNamespace);
	ClassName	= std::wstring(pData->szClassName);
	MethodName	= std::wstring(pData->szMethodName);
	Argument	= std::wstring(pData->szArgument);
}