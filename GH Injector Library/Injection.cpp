/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

#include "pch.h"

#include "Injection.h"

DWORD HijackHandle(INJECTIONDATA_INTERNAL & Data, ERROR_DATA & error_data);

DWORD InitErrorStruct(const INJECTIONDATA_INTERNAL & Data, int Native, DWORD ErrorCode, const ERROR_DATA & error_data);

DWORD __stdcall InjectA(INJECTIONDATAA * pData)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	LOG(0, "InjectA called with pData = %p\n", pData);

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
	
	INJECTIONDATA_INTERNAL data_internal(pData);
	DWORD Ret = Inject_Internal(&data_internal);
	pData->hDllOut = data_internal.hDllOut;

	return Ret;
}

DWORD __stdcall InjectW(INJECTIONDATAW * pData)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	LOG(0, "InjectW called with pData = %p\n", pData);

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

	INJECTIONDATA_INTERNAL data_internal(pData);
	DWORD Ret = Inject_Internal(&data_internal);
	pData->hDllOut = data_internal.hDllOut;

	return Ret;	
}

DWORD __stdcall Inject_Internal(INJECTIONDATA_INTERNAL * pData)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	LOG(0, "Inject_Internal called with pData = %p\n", pData);

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

		return InitErrorStruct(Data, -1, INJ_ERR_IMPORT_HANDLER_NOT_DONE, error_data);
	}

	if (Data.Mode == INJECTION_MODE::IM_LdrpLoadDllInternal && !IsWin10OrGreater())
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "LdrpLoadDllInternal is only supported on Windows 10\n");

		return InitErrorStruct(Data, -1, INJ_ERR_NOT_SUPPORTED, error_data);
	}
		
	if (Data.DllPath.empty())
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Invalid path provided (empty string)\n");

		return InitErrorStruct(Data, -1, INJ_ERR_INVALID_FILEPATH, error_data);
	}

	if (!FileExistsW(Data.DllPath))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(0, "File doesn't exist: %08X\n", error_data.AdvErrorCode);

		return InitErrorStruct(Data, -1, INJ_ERR_FILE_DOESNT_EXIST, error_data);
	}

	if (PathIsRelativeW(Data.DllPath.c_str()))
	{
		wchar_t buffer[MAX_PATH * 2]{ 0 };
		auto win_ret = GetFullPathNameW(Data.DllPath.c_str(), sizeof(buffer) / sizeof(wchar_t), buffer, nullptr);
		if (!win_ret || win_ret >= sizeof(buffer) / sizeof(wchar_t))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(0, "Failed to resolve absolute file path: %08X\n", error_data.AdvErrorCode);

			return InitErrorStruct(Data, -1, INJ_ERR_FAILED_TO_RESOLVE_PATH, error_data);
		}

		Data.DllPath = buffer;
	}

	if (!Data.ProcessID)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Invalid process identifier specified\n");

		return InitErrorStruct(Data, -1, INJ_ERR_INVALID_PID, error_data);
	}

	if (Data.Flags & INJ_MM_MAP_FROM_MEMORY)
	{
		Data.Flags ^= INJ_MM_MAP_FROM_MEMORY;
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

			return InitErrorStruct(Data, -1, dwRet, error_data);
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

			return InitErrorStruct(Data, -1, dwRet, error_data);
		}

		LOG(0, "Path of renamed dll: %ls\n", Data.DllPath.c_str());
	}

	HANDLE hTargetProc = nullptr;
	if (Data.Flags & INJ_HIJACK_HANDLE)
	{
		if (Data.hHandleValue)
		{
			LOG(0, "hHandleValue = %08X\n", Data.hHandleValue);
			
			hTargetProc = MPTR(Data.hHandleValue);
		}
		else
		{
			LOG(0, "Forwarding call to handle hijacking\n");
			
			return HijackHandle(Data, error_data);
		}
	}
	else
	{
		DWORD access_mask = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION;
		if (Data.Method == LAUNCH_METHOD::LM_NtCreateThreadEx)
		{
			access_mask |= PROCESS_CREATE_THREAD;
		}

		hTargetProc = OpenProcess(access_mask, FALSE, Data.ProcessID);
		if (!hTargetProc)
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(0, "OpenProcess failed: %08X\n", (DWORD)error_data.AdvErrorCode);

			return InitErrorStruct(Data, -1, INJ_ERR_CANT_OPEN_PROCESS, error_data);
		}
	}

	DWORD handle_info = 0;
	if (!hTargetProc || !GetHandleInformation(hTargetProc, &handle_info))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(0, "Invalid process handle: %08X\n", (DWORD)error_data.AdvErrorCode);

		return InitErrorStruct(Data, -1, INJ_ERR_INVALID_PROC_HANDLE, error_data);
	}

	LOG(0, "Attached to target process\n");

	wchar_t szExePath[MAX_PATH * 2]{ 0 };
	DWORD size_inout = sizeof(szExePath) / sizeof(szExePath[0]);
	if (!QueryFullProcessImageNameW(hTargetProc, NULL, szExePath, &size_inout))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(0, "QueryFullProcessImageNameW failed: %08X\n", (DWORD)error_data.AdvErrorCode);

		return InitErrorStruct(Data, -1, INJ_ERR_CANT_GET_EXE_FILENAME, error_data);
	}

	auto ExePath	= std::wstring(szExePath);
	auto ExeNamePos = ExePath.find_last_of('\\');

	if (ExeNamePos == std::string::npos)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Failed to extract exe name from path\n");

		return InitErrorStruct(Data, -1, INJ_ERR_INVALID_EXE_PATH, error_data);
	}

	Data.TargetProcessExeFileName = ExePath.substr(ExeNamePos + 1);

	LOG(0, "Target process name = %ls\n", Data.TargetProcessExeFileName.c_str());

	LOG(0, "Validating specified file\n");

	DWORD FileErr = FILE_ERR_SUCCESS;
	bool native_target = true;
#ifdef _WIN64
	native_target = IsNativeProcess(hTargetProc);
	if (native_target)
	{
		FileErr = ValidateDllFile(Data.DllPath, IMAGE_FILE_MACHINE_AMD64);
	}
	else
	{
		FileErr = ValidateDllFile(Data.DllPath, IMAGE_FILE_MACHINE_I386);
	}
#else
	FileErr = ValidateDllFile(Data.DllPath, IMAGE_FILE_MACHINE_I386);
#endif

	if (FileErr != FILE_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, FileErr);

		LOG(0, "Invalid file specified\n");

		return InitErrorStruct(Data, native_target, INJ_ERR_PLATFORM_MISMATCH, error_data);
	}

	LOG(0, "File validated and prepared for injection:\n %ls\n", Data.DllPath.c_str());
	
	HINSTANCE hOut = NULL;

	INJECTION_SOURCE source;
	source.DllPath = Data.DllPath;

#ifdef _WIN64
	if (native_target)
	{
		RetVal = InjectDLL(source, hTargetProc, Data.Mode, Data.Method, Data.Flags, hOut, Data.Timeout, error_data);
	}
	else
	{		
		RetVal = InjectDLL_WOW64(source, hTargetProc, Data.Mode, Data.Method, Data.Flags, hOut, Data.Timeout, error_data);
	}	
#else
	RetVal = InjectDLL(source, hTargetProc, Data.Mode, Data.Method, Data.Flags, hOut, Data.Timeout, error_data);
#endif

	LOG(0, "Injection finished\n");

	if (!(Data.Flags & INJ_HIJACK_HANDLE))
	{
		CloseHandle(hTargetProc);
	}
	
	Data.hDllOut = hOut;

	return InitErrorStruct(Data, native_target, RetVal, error_data);
}

DWORD InitErrorStruct(const INJECTIONDATA_INTERNAL & Data, int Native, DWORD ErrorCode, const ERROR_DATA & error_data)
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
		info.RawData					= Data.RawData;
		info.RawSize					= Data.RawSize;

		info.ErrorCode		= ErrorCode;
		info.AdvErrorCode	= error_data.AdvErrorCode;
		info.SourceFile		= error_data.szFileName;
		info.FunctionName	= error_data.szFunctionName;
		info.Line			= error_data.Line;

		info.IsDotNet = false;

		ErrorLog(info);
	}

	return ErrorCode;
}

DWORD HijackHandle(INJECTIONDATA_INTERNAL & Data, ERROR_DATA & error_data)
{
	LOG(1, "Begin HijackHandle\n");

	DWORD access_mask = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;
	if (Data.Method == LAUNCH_METHOD::LM_NtCreateThreadEx)
	{
		access_mask |= PROCESS_CREATE_THREAD;
	}

	auto handles = FindProcessHandles(Data.ProcessID, access_mask);
	if (handles.empty())
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "No compatible handle found\n");

		return InitErrorStruct(Data, true, INJ_ERR_HIJACK_NO_HANDLES, error_data);
	}

	INJECTIONDATAW hijack_data{ 0 };
	hijack_data.Mode				= INJECTION_MODE::IM_LdrLoadDll;
	hijack_data.Method				= LAUNCH_METHOD::LM_NtCreateThreadEx;
	hijack_data.Timeout				= Data.Timeout;
	hijack_data.GenerateErrorLog	= Data.GenerateErrorLog;
	hijack_data.Flags				= NULL;
	
	auto FullModPath = g_RootPathW + GH_INJ_MOD_NAMEW;
	if (!StdWStringToWCharArray(FullModPath, hijack_data.szDllPath, sizeof(hijack_data.szDllPath) / sizeof(wchar_t)))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "String exceeded %d characters: %ls\n", sizeof(hijack_data.szDllPath) / sizeof(wchar_t), FullModPath.c_str());

		return InitErrorStruct(Data, true, INJ_ERR_STRING_TOO_LONG, error_data);
	}

	INJECTIONDATAW injection_data{ 0 };
	injection_data.ProcessID		= Data.ProcessID;
	injection_data.Mode				= Data.Mode;
	injection_data.Method			= Data.Method;
	injection_data.Flags			= Data.Flags;
	injection_data.Timeout			= Data.Timeout;
	injection_data.GenerateErrorLog = Data.GenerateErrorLog;
	if (!StdWStringToWCharArray(Data.DllPath, injection_data.szDllPath, sizeof(injection_data.szDllPath) / sizeof(wchar_t)))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "String exceeded %d characters: %ls\n", sizeof(hijack_data.szDllPath) / sizeof(wchar_t), Data.DllPath.c_str());

		return InitErrorStruct(Data, true, INJ_ERR_STRING_TOO_LONG,  error_data);
	}
	
	if (injection_data.Flags & INJ_SCRAMBLE_DLL_NAME)
	{
		injection_data.Flags ^= INJ_SCRAMBLE_DLL_NAME;
	}

	if (injection_data.Flags & INJ_LOAD_DLL_COPY)
	{
		injection_data.Flags ^= INJ_LOAD_DLL_COPY;
	}

	DWORD LastErrCode	= INJ_ERR_SUCCESS;
	HANDLE hHijackProc	= nullptr;
	for (const auto & i : handles)
	{
		hHijackProc = OpenProcess(access_mask | PROCESS_CREATE_THREAD, FALSE, i.OwnerPID);
		if (!hHijackProc)
		{
			LastErrCode = INJ_ERR_CANT_OPEN_PROCESS;
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(1, "Failed to attach to process %06X\n", i.OwnerPID);

			continue;
		}

		LOG(1, "Attached to process %06X\n", i.OwnerPID);
					
		if (!IsElevatedProcess(hHijackProc) || !IsNativeProcess(hHijackProc))
		{
			LastErrCode = INJ_ERR_HIJACK_NO_NATIVE_HANDLE;
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(1, "Process isn't elevated or native\n");

			CloseHandle(hHijackProc);
			
			continue;
		}

		ResetEvent(g_hRunningEvent);

		hijack_data.ProcessID = i.OwnerPID;
		DWORD inj_ret = InjectW(&hijack_data);

		SetEvent(g_hRunningEvent);

		if (inj_ret || !hijack_data.hDllOut)
		{
			LastErrCode = INJ_ERR_HIJACK_INJ_FAILED;
			INIT_ERROR_DATA(error_data, inj_ret);

			LOG(1, "Failed to load injection module into process %06X: %08X\n", i.OwnerPID, inj_ret);

			CloseHandle(hHijackProc);
			
			continue;
		}

		LOG(1, "Injection module loaded into hijack process\n");

		HINSTANCE hInjectionModuleEx = hijack_data.hDllOut;
		f_Routine pRemoteInjectW = ReCa<f_Routine>(ReCa<UINT_PTR>(InjectW) - ReCa<UINT_PTR>(g_hInjMod) + ReCa<UINT_PTR>(hInjectionModuleEx));
		
		void * pArg = VirtualAllocEx(hHijackProc, nullptr, sizeof(INJECTIONDATAW), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pArg)
		{
			LastErrCode = INJ_ERR_HIJACK_OUT_OF_MEMORY_EXT;
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(1, "VirtualAllocEx failed: %08X\n", error_data.AdvErrorCode);

			EjectHijackLibrary(hHijackProc, hInjectionModuleEx);

			CloseHandle(hHijackProc);
			
			continue;
		}

		injection_data.hHandleValue = i.hValue;
		if (!WriteProcessMemory(hHijackProc, pArg, &injection_data, sizeof(INJECTIONDATAW), nullptr))
		{
			LastErrCode = INJ_ERR_HIJACK_WPM_FAIL;
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(1, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

			VirtualFreeEx(hHijackProc, pArg, 0, MEM_RELEASE);
			EjectHijackLibrary(hHijackProc, hInjectionModuleEx);

			CloseHandle(hHijackProc);
			
			continue;
		}

		LOG(1, "Handle value: %04X\n", i.hValue);

		injection_data.hHandleValue = 0;

		LOG(1, "Injection data written to hijack process\n");

		bool b_Ready = false;
		bool * p_g_LibraryState = ReCa<bool *>(ReCa<UINT_PTR>(&g_LibraryState) - ReCa<UINT_PTR>(g_hInjMod) + ReCa<UINT_PTR>(hInjectionModuleEx));

		auto Timer = GetTickCount64();
		while (GetTickCount64() - Timer < INJ_HIJACK_TIMEOUT)
		{
			if (!ReadProcessMemory(hHijackProc, p_g_LibraryState, &b_Ready, sizeof(b_Ready), nullptr) || b_Ready)
			{
				break;
			}

			auto dwWaitRet = WaitForSingleObject(g_hInterruptEvent, 10);
			if (dwWaitRet == WAIT_OBJECT_0)
			{
				LOG(1, "Interrupt!\n");
				LastErrCode = INJ_ERR_INTERRUPT;

				SetEvent(g_hInterruptedEvent);

				VirtualFreeEx(hHijackProc, pArg, 0, MEM_RELEASE);
				EjectHijackLibrary(hHijackProc, hInjectionModuleEx);
	
				CloseHandle(hHijackProc);

				break;
			}
		}

		if (!b_Ready)
		{
			LOG(1, "Hijack library timed out\n");

			VirtualFreeEx(hHijackProc, pArg, 0, MEM_RELEASE);
			EjectHijackLibrary(hHijackProc, hInjectionModuleEx);
	
			CloseHandle(hHijackProc);

			continue;
		}
		else
		{
			LOG(1, "Hijack library is ready\n");
		}

		DWORD hijack_ret = INJ_ERR_SUCCESS;
		DWORD remote_ret = StartRoutine(hHijackProc, pRemoteInjectW, pArg, LAUNCH_METHOD::LM_NtCreateThreadEx, NULL, hijack_ret, Data.Timeout, error_data);
				
		INJECTIONDATAW data_out{ 0 };
		ReadProcessMemory(hHijackProc, pArg, &data_out, sizeof(INJECTIONDATAW), nullptr);
		
		if (remote_ret != SR_NTCTE_ERR_REMOTE_TIMEOUT || remote_ret == SR_ERR_INTERRUPT)
		{
			if (remote_ret == SR_ERR_INTERRUPT)
			{
				ResetEvent(g_hInterruptEvent);
				ResetEvent(g_hInterruptedEvent);
				LOG(1, "Interrupt! Attempting to interrupt hijack injection\n");
			}
			else
			{
				LOG(1, "Hijack injection timed out\n");
			}

			ERROR_DATA interrupt_data;
			remote_ret	= 0;
			DWORD ret	= 0;
			f_Routine pInterruptInjectionEx	= ReCa<f_Routine>(ReCa<UINT_PTR>(InterruptInjectionEx) - ReCa<UINT_PTR>(g_hInjMod) + ReCa<UINT_PTR>(hInjectionModuleEx));

			ret = StartRoutine(hHijackProc, pInterruptInjectionEx, MPTR(INJ_EJECT_TIMEOUT), LAUNCH_METHOD::LM_NtCreateThreadEx, NULL, remote_ret, INJ_EJECT_TIMEOUT, interrupt_data);

			if (ret != SR_ERR_SUCCESS)
			{
				LOG(1, "Attempt to interrupt hijack injection failed: %08X\n", ret);
			}
			else if (remote_ret != (DWORD)true)
			{
				LOG(1, "Failed to interrupt hijack injection\n");
			}
		}

		VirtualFreeEx(hHijackProc, pArg, 0, MEM_RELEASE);
		EjectHijackLibrary(hHijackProc, hInjectionModuleEx, false);

		CloseHandle(hHijackProc);

		if (remote_ret != SR_ERR_SUCCESS)
		{
			LastErrCode = remote_ret;

			LOG(1, "StartRoutine failed: %08X\n", remote_ret);

			continue;
		}

		if (hijack_ret != INJ_ERR_SUCCESS || !data_out.hDllOut)
		{
			LastErrCode = INJ_ERR_HIJACK_REMOTE_INJ_FAIL;
			INIT_ERROR_DATA(error_data, hijack_ret);

			LOG(1, "Hijack injection failed: %08X\n", hijack_ret);

			continue;
		}

		LOG(1, "Hijack injection succeeded\nImagebase = %p\n", ReCa<void *>(data_out.hDllOut));

		Data.hDllOut = data_out.hDllOut;

		LastErrCode = INJ_ERR_SUCCESS;

		break;
	}

	LOG(1, "End HijackHandle\n");

	return InitErrorStruct(Data, true, LastErrCode, error_data);
}

DWORD __stdcall Memory_Inject(MEMORY_INJECTIONDATA * pData)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	LOG(0, "Memory_Inject called with pData = %p\n", pData);

	if (WaitForSingleObject(g_hRunningEvent, 0) == WAIT_OBJECT_0)
	{
		LOG(0, "Different injection in progress. Wait for the other injection to finish first.\n");

		return INJ_ERR_ALREADY_RUNNING;
	}

	SetEvent(g_hRunningEvent);
	ResetEvent(g_hInterruptEvent);
	ResetEvent(g_hInterruptedEvent);

	if (!pData)
	{
		LOG(0, "pData is invalid\n");

		return INJ_ERR_NO_DATA;
	}

	if (!pData->RawData)
	{
		LOG(0, "No raw data\n");

		return INJ_ERR_NO_RAW_DATA;
	}

	pData->Flags |= INJ_MM_MAP_FROM_MEMORY;

	DWORD RetVal = INJ_ERR_SUCCESS;

	ERROR_DATA error_data{ 0 };
	INJECTIONDATA_INTERNAL Data(pData);

	RetVal = GetImportState();
	if (RetVal != INJ_ERR_SUCCESS)
	{
		LOG(0, "Resolving imports failed: %08X\n", RetVal);

		error_data = import_handler_error_data;

		return InitErrorStruct(Data, -1, INJ_ERR_IMPORT_HANDLER_NOT_DONE, error_data);
	}

	pData->Mode = INJECTION_MODE::IM_ManualMap;
	pData->Flags |= INJ_MM_MAP_FROM_MEMORY;

	if (!Data.ProcessID)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Invalid process identifier specified\n");

		return InitErrorStruct(Data, -1, INJ_ERR_INVALID_PID, error_data);
	}

	HANDLE hTargetProc = nullptr;
	if (Data.Flags & INJ_HIJACK_HANDLE)
	{
		if (Data.hHandleValue)
		{
			LOG(0, "hHandleValue = %08X\n", Data.hHandleValue);
			
			hTargetProc = MPTR(Data.hHandleValue);
		}
		else
		{
			LOG(0, "Forwarding call to handle hijacking\n");
			
			return HijackHandle(Data, error_data);
		}
	}
	else
	{
		DWORD access_mask = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION;
		if (Data.Method == LAUNCH_METHOD::LM_NtCreateThreadEx)
		{
			access_mask |= PROCESS_CREATE_THREAD;
		}

		hTargetProc = OpenProcess(access_mask, FALSE, Data.ProcessID);
		if (!hTargetProc)
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(0, "OpenProcess failed: %08X\n", (DWORD)error_data.AdvErrorCode);

			return InitErrorStruct(Data, -1, INJ_ERR_CANT_OPEN_PROCESS, error_data);
		}
	}

	DWORD handle_info = 0;
	if (!hTargetProc || !GetHandleInformation(hTargetProc, &handle_info))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(0, "Invalid process handle: %08X\n", (DWORD)error_data.AdvErrorCode);

		return InitErrorStruct(Data, -1, INJ_ERR_INVALID_PROC_HANDLE, error_data);
	}

	LOG(0, "Attached to target process\n");

	wchar_t szExePath[MAX_PATH * 2]{ 0 };
	DWORD size_inout = sizeof(szExePath) / sizeof(szExePath[0]);
	if (!QueryFullProcessImageNameW(hTargetProc, NULL, szExePath, &size_inout))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(0, "QueryFullProcessImageNameW failed: %08X\n", (DWORD)error_data.AdvErrorCode);

		return InitErrorStruct(Data, -1, INJ_ERR_CANT_GET_EXE_FILENAME, error_data);
	}

	auto ExePath	= std::wstring(szExePath);
	auto ExeNamePos = ExePath.find_last_of('\\');

	if (ExeNamePos == std::string::npos)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Failed to extract exe name from path\n");

		return InitErrorStruct(Data, -1, INJ_ERR_INVALID_EXE_PATH, error_data);
	}

	Data.TargetProcessExeFileName = ExePath.substr(ExeNamePos + 1);

	LOG(0, "Target process name = %ls\n", Data.TargetProcessExeFileName.c_str());

	LOG(0, "Validating specified file\n");

	DWORD FileErr = FILE_ERR_SUCCESS;
	bool native_target = true;
#ifdef _WIN64
	native_target = IsNativeProcess(hTargetProc);
	if (native_target)
	{
		FileErr = ValidateDllFileInMemory(Data.RawData, Data.RawSize, IMAGE_FILE_MACHINE_AMD64);
	}
	else
	{
		FileErr = ValidateDllFileInMemory(Data.RawData, Data.RawSize, IMAGE_FILE_MACHINE_I386);
	}
#else
	FileErr = ValidateDllFileInMemory(Data.RawData, Data.RawSize, IMAGE_FILE_MACHINE_I386);
#endif

	if (FileErr != FILE_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, FileErr);

		LOG(0, "Invalid file specified\n");

		return InitErrorStruct(Data, native_target, INJ_ERR_PLATFORM_MISMATCH, error_data);
	}

	LOG(0, "File validated and prepared for injection\n");

	HINSTANCE hOut = NULL;

	INJECTION_SOURCE Source;
	Source.FromMemory	= true;
	Source.RawData		= Data.RawData;
	Source.RawSize		= Data.RawSize;

#ifdef _WIN64
	if (native_target)
	{
		RetVal = InjectDLL(Source, hTargetProc, Data.Mode, Data.Method, Data.Flags, hOut, Data.Timeout, error_data);
	}
	else
	{		
		RetVal = InjectDLL_WOW64(Source, hTargetProc, Data.Mode, Data.Method, Data.Flags, hOut, Data.Timeout, error_data);
	}	
#else
	RetVal = InjectDLL(Source, hTargetProc, Data.Mode, Data.Method, Data.Flags, hOut, Data.Timeout, error_data);
#endif

	LOG(0, "Injection finished\n");

	if (!(Data.Flags & INJ_HIJACK_HANDLE))
	{
		CloseHandle(hTargetProc);
	}
	
	pData->hDllOut = hOut;

	return InitErrorStruct(Data, native_target, RetVal, error_data);
}

HRESULT __stdcall GetVersionA(char * out, size_t cb_size)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	if (!out)
	{
		LOG(0, "GetVersionA: out = nullptr\n");

		return E_INVALIDARG;
	}

	if (sizeof(GH_INJ_VERSIONA) > cb_size)
	{
		LOG(0, "GetVersionA: buffer too small (%d bytes required)\n", (int)sizeof(GH_INJ_VERSIONA));

		return TYPE_E_BUFFERTOOSMALL;
	}

	std::string s(GH_INJ_VERSIONA);
	s.copy(out, s.length());
	out[s.length()] = '\0';

	return S_OK;
}

HRESULT __stdcall GetVersionW(wchar_t * out, size_t cb_size)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	if (!out)
	{
		LOG(0, "GetVersionW: out = nullptr\n");

		return E_INVALIDARG;
	}

	if (sizeof(GH_INJ_VERSIONW) > cb_size)
	{
		LOG(0, "GetVersionA: buffer too small (%d bytes required)\n", (int)sizeof(GH_INJ_VERSIONW));

		return TYPE_E_BUFFERTOOSMALL;
	}

	std::wstring s(GH_INJ_VERSIONW);
	s.copy(out, s.length());
	out[s.length()] = '\0';

	return S_OK;
}

DWORD __stdcall GetSymbolState()
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	if (sym_ntdll_native_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
	{
		return INJ_ERR_SYMBOL_INIT_NOT_DONE;
	}

	DWORD sym_ret = sym_ntdll_native_ret.get();
	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		LOG(0, "Native symbol loading failed: %08X\n", sym_ret);

		return sym_ret;
	}

#ifdef _WIN64
	if (sym_ntdll_wow64_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
	{
		return INJ_ERR_SYMBOL_INIT_NOT_DONE;
	}

	sym_ret = sym_ntdll_wow64_ret.get();
	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		LOG(0, "WOW64 symbol loading failed: %08X\n", sym_ret);

		return sym_ret;
	}
#endif

	if (GetOSVersion() == g_Win7)
	{
		if (sym_kernel32_native_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
		{
			return INJ_ERR_SYMBOL_INIT_NOT_DONE;
		}

		sym_ret = sym_kernel32_native_ret.get();
		if (sym_ret != SYMBOL_ERR_SUCCESS)
		{
			LOG(0, "Native symbol loading failed: %08X\n", sym_ret);

			return sym_ret;
		}

#ifdef _WIN64
		if (sym_kernel32_wow64_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
		{
			return INJ_ERR_SYMBOL_INIT_NOT_DONE;
		}

		sym_ret = sym_kernel32_wow64_ret.get();
		if (sym_ret != SYMBOL_ERR_SUCCESS)
		{
			LOG(0, "WOW64 symbol loading failed: %08X\n", sym_ret);

			return sym_ret;
		}
#endif
	}

	LOG(0, "All symbols loaded\n");

	return SYMBOL_ERR_SUCCESS;
}

DWORD __stdcall GetImportState()
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__

	if (import_handler_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
	{
		return INJ_ERR_IMPORT_HANDLER_NOT_DONE;
	}

#ifdef _WIN64
	if (import_handler_wow64_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
	{
		return INJ_ERR_IMPORT_HANDLER_NOT_DONE;
	}
#endif

	DWORD imp_ret = import_handler_ret.get();
	if (imp_ret != INJ_ERR_SUCCESS)
	{
		LOG(0, "Import handler (native) failed: %08X\n", imp_ret);

		return imp_ret;
	}

#ifdef _WIN64
	imp_ret = import_handler_wow64_ret.get();
	if (imp_ret != INJ_ERR_SUCCESS)
	{
		LOG(0, "Import handler (wow64) failed: %08X\n", imp_ret);

		return imp_ret;
	}
#endif

	LOG(0, "Import handler finished\n");

	return INJ_ERR_SUCCESS;
}

INJECTIONDATA_INTERNAL::INJECTIONDATA_INTERNAL(const INJECTIONDATAA * pData)
{
	DllPath				= CharArrayToStdWstring(pData->szDllPath);
	ProcessID			= pData->ProcessID;
	Mode				= pData->Mode;
	Method				= pData->Method;
	Flags				= pData->Flags;
	Timeout				= pData->Timeout;
	hHandleValue		= pData->hHandleValue;
	GenerateErrorLog	= pData->GenerateErrorLog;
	hDllOut				= NULL;
}

INJECTIONDATA_INTERNAL::INJECTIONDATA_INTERNAL(const INJECTIONDATAW * pData)
{
	DllPath				= std::wstring(pData->szDllPath);
	ProcessID			= pData->ProcessID;
	Mode				= pData->Mode;
	Method				= pData->Method;
	Flags				= pData->Flags;
	Timeout				= pData->Timeout;
	hHandleValue		= pData->hHandleValue;
	GenerateErrorLog	= pData->GenerateErrorLog;
	hDllOut				= NULL;
}

INJECTIONDATA_INTERNAL::INJECTIONDATA_INTERNAL(const MEMORY_INJECTIONDATA * pData)
{
	RawData				= pData->RawData;
	RawSize				= pData->RawSize;
	ProcessID			= pData->ProcessID;
	Mode				= pData->Mode;
	Method				= pData->Method;
	Flags				= pData->Flags;
	Timeout				= pData->Timeout;
	hHandleValue		= pData->hHandleValue;
	GenerateErrorLog	= pData->GenerateErrorLog;
	hDllOut				= NULL;
}

INJECTIONDATA_INTERNAL::INJECTIONDATA_INTERNAL()
{
	RawData				= nullptr;
	RawSize				= 0;
	ProcessID			= 0;
	Mode				= INJECTION_MODE::IM_LoadLibraryExW;
	Method				= LAUNCH_METHOD::LM_NtCreateThreadEx;
	Flags				= NULL;
	Timeout				= 2000;
	hHandleValue		= 0;
	hDllOut				= NULL;
	GenerateErrorLog	= true;
}