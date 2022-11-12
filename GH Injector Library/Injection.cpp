#include "pch.h"

#include "Injection.h"

DWORD InitErrorStruct(const wchar_t * szDllPath, INJECTIONDATAW * pData, int bNative, DWORD ErrorCode, ERROR_DATA error_data);

DWORD InjectDLL(const wchar_t * szDllFile, HANDLE hTargetProc, INJECTION_MODE im, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD Timeout, ERROR_DATA & error_data);

DWORD HijackHandle(INJECTIONDATAW * pData, ERROR_DATA & error_data);

DWORD InitErrorStruct(const wchar_t * szDllPath, INJECTIONDATAW * pData, int bNative, DWORD ErrorCode, ERROR_DATA error_data)
{
	ResetEvent(g_hRunningEvent);

	if (!ErrorCode)
	{
		return INJ_ERR_SUCCESS;
	}
	
	if (pData->GenerateErrorLog)
	{
		ERROR_INFO info{ 0 };
		info.szDllFileName				= szDllPath;
		info.szTargetProcessExeFileName = pData->szTargetProcessExeFileName;
		info.TargetProcessId			= pData->ProcessID;
		info.InjectionMode				= pData->Mode;
		info.LaunchMethod				= pData->Method;
		info.Flags						= pData->Flags;
		info.ErrorCode					= ErrorCode;
		info.AdvErrorCode				= error_data.AdvErrorCode;
		info.HandleValue				= pData->hHandleValue;
		info.bNative					= bNative;
		info.szSourceFile				= error_data.szFileName;
		info.szFunctionName				= error_data.szFunctionName;
		info.Line						= error_data.Line;

		ErrorLog(info);
	}

	return ErrorCode;
}

DWORD __stdcall InjectA(INJECTIONDATAA * pData)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	LOG(0, "InjectA called with pData = %p\n", pData);

	ERROR_DATA error_data{ 0 };

	if (!pData)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "pData is invalid\n");

		return InitErrorStruct(nullptr, ReCa<INJECTIONDATAW *>(pData), -1, INJ_ERR_NO_DATA, error_data);
	}
	
	if (!pData->szDllPath)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Invalid path\n");

		return InitErrorStruct(nullptr, ReCa<INJECTIONDATAW *>(pData), -1, INJ_ERR_INVALID_FILEPATH, error_data);
	}
	
	INJECTIONDATAW data{ 0 };
	size_t len_out = 0;
	size_t max_len = sizeof(data.szDllPath) / sizeof(wchar_t);
	HRESULT hr = StringCchLengthA(pData->szDllPath, max_len, &len_out);
	if (FAILED(hr) || !len_out)
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		LOG(0, "StringCchLengthA failed: %08X\n", hr);

		return InitErrorStruct(nullptr, ReCa<INJECTIONDATAW *>(pData), -1, INJ_ERR_STRINGC_XXX_FAIL, error_data);
	}

	auto err = mbstowcs_s(&len_out, data.szDllPath, max_len, pData->szDllPath, max_len);
	if (err)
	{
		INIT_ERROR_DATA(error_data, (DWORD)err);

		LOG(0, "mbstowcs_s failed: %08X\n", (DWORD)err);

		return InitErrorStruct(nullptr, ReCa<INJECTIONDATAW *>(pData), -1, INJ_ERR_STR_CONVERSION_TO_W_FAILED, error_data);
	}

	data.ProcessID			= pData->ProcessID;
	data.Mode				= pData->Mode;
	data.Method				= pData->Method;
	data.Flags				= pData->Flags;
	data.Timeout			= pData->Timeout;
	data.hHandleValue		= pData->hHandleValue;
	data.GenerateErrorLog	= pData->GenerateErrorLog;

	LOG(0, "Initialized INJECTIONDATAW\n");

	LOG(0, "Forwarding call to InjectW\n");

	DWORD Ret = InjectW(&data);
	pData->hDllOut = data.hDllOut;

	return Ret;
}

DWORD __stdcall InjectW(INJECTIONDATAW * pData)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	LOG(0, "InjectW called with pData = %p\n", pData);
	
	ERROR_DATA error_data{ 0 };
	DWORD RetVal = INJ_ERR_SUCCESS;

	if (WaitForSingleObject(g_hRunningEvent, 0) == WAIT_OBJECT_0)
	{
		return INJ_ERR_ALREADY_RUNNING;
	}

	if (!pData)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "pData is invalid\n");

		return InitErrorStruct(nullptr, pData, -1, INJ_ERR_NO_DATA, error_data);
	}

	SetEvent(g_hRunningEvent);
	ResetEvent(g_hInterruptEvent);
	ResetEvent(g_hInterruptedEvent);

	if (import_handler_ret.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
	{
		LOG(0, "PDB download incomplete or imports not resolved\n");

		return InitErrorStruct(nullptr, pData, -1, INJ_ERR_IMPORT_HANDLER_NOT_DONE, error_data);
	}

	RetVal = import_handler_ret.get();
	if (RetVal != INJ_ERR_SUCCESS)
	{
		LOG(0, "Resolving imports failed: %08X\n", RetVal);

		error_data = import_handler_error_data;

		return RetVal;
	}

	if (pData->Mode == INJECTION_MODE::IM_LdrpLoadDllInternal && !IsWin10OrGreater())
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "LdrpLoadDllInternal is only supported on Windows 10\n");

		return InitErrorStruct(nullptr, pData, -1, INJ_ERR_NOT_SUPPORTED, error_data);
	}
		
	if (!pData->szDllPath)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Invalid path\n");

		return InitErrorStruct(nullptr, pData, -1, INJ_ERR_INVALID_FILEPATH, error_data);
	}

	const wchar_t * szDllPath = pData->szDllPath;

	if (!FileExists(szDllPath))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(0, "File doesn't exist: %08X\n", error_data.AdvErrorCode);

		return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_FILE_DOESNT_EXIST, error_data);
	}

	if (!pData->ProcessID)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Invalid process identifier specified\n");

		return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_INVALID_PID, error_data);
	}

	if (pData->Flags & INJ_LOAD_DLL_COPY)
	{
		LOG(0, "Copying dll into temp directory\n");

		size_t len_out = 0;
		HRESULT hr = StringCchLengthW(pData->szDllPath, MAXPATH_IN_TCHAR, &len_out);
		if (FAILED(hr) || !len_out)
		{
			INIT_ERROR_DATA(error_data, (DWORD)hr);

			LOG(0, "StringCchLengthW failed: %08X\n", hr);

			return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_STRINGC_XXX_FAIL, error_data);
		}

		const wchar_t * pFileName = pData->szDllPath;
		pFileName += len_out;
		while (*(--pFileName - 1) != '\\');

		wchar_t new_path[MAXPATH_IN_TCHAR]{ 0 };
		if (!GetTempPathW(MAXPATH_IN_TCHAR, new_path))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(0, "GetTempPathW failed: %08X\n", error_data.AdvErrorCode);

			return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_CANT_GET_TEMP_DIR, error_data);
		}

		hr = StringCchCatW(new_path, MAXPATH_IN_TCHAR, pFileName);
		if (FAILED(hr))
		{
			INIT_ERROR_DATA(error_data, (DWORD)hr);

			LOG(0, "StringCchCatW failed: %08X\n", hr);

			return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_STRINGC_XXX_FAIL, error_data);
		}

		if (!CopyFileW(pData->szDllPath, new_path, FALSE))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(0, "CopyFileW failed: %08X\n", error_data.AdvErrorCode);

			return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_CANT_COPY_FILE, error_data);
		}

		hr = StringCbCopyW(pData->szDllPath, sizeof(pData->szDllPath), new_path);
		if (FAILED(hr))
		{
			INIT_ERROR_DATA(error_data, (DWORD)hr);

			LOG(0, "StringCbCopyW failed: %08X\n", hr);

			return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_STRINGC_XXX_FAIL, error_data);
		}

		LOG(0, "Path of dll copy: %ls\n", pData->szDllPath);
	}

	if (pData->Flags & INJ_SCRAMBLE_DLL_NAME)
	{
		LOG(0, "Scrambling dll name\n");

		wchar_t new_name[15]{ 0 };
		UINT seed = rand() + pData->Flags;
		LARGE_INTEGER pfc{ 0 };
		QueryPerformanceCounter(&pfc);
		seed += pfc.LowPart;
		srand(seed);

		for (UINT i = 0; i != 10; ++i)
		{
			auto val = rand() % 3;
			if (val == 0)
			{
				val = rand() % 10;
				new_name[i] = wchar_t('0' + val);
			}
			else if (val == 1)
			{
				val = rand() % 26;
				new_name[i] = wchar_t('A' + val);
			}
			else
			{
				val = rand() % 26;
				new_name[i] = wchar_t('a' + val);
			}
		}
		new_name[10] = '.';
		new_name[11] = 'd';
		new_name[12] = 'l';
		new_name[13] = 'l';
		new_name[14] = '\0';

		wchar_t OldFilePath[MAXPATH_IN_TCHAR]{ 0 };
		HRESULT hr = StringCchCopyW(OldFilePath, MAXPATH_IN_TCHAR, pData->szDllPath);
		if (FAILED(hr))
		{
			INIT_ERROR_DATA(error_data, (DWORD)hr);

			LOG(0, "StringCchCopyW failed: %08X\n", hr);

			return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_STRINGC_XXX_FAIL, error_data);
		}

		wchar_t * pFileName = wcsrchr(pData->szDllPath, '\\');
		if (!pFileName)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(0, "wcsrchr failed\n");

			ResetEvent(g_hRunningEvent);

			return INJ_ERR_INVALID_PATH_SEPERATOR;
		}
		else
		{
			++pFileName;
		}

		auto size_delta = pFileName - pData->szDllPath;

		hr = StringCbCopyW(pFileName, sizeof(pData->szDllPath) - size_delta, new_name);
		if (FAILED(hr))
		{
			INIT_ERROR_DATA(error_data, (DWORD)hr);

			LOG(0, "StringCbCopyW failed: %08X\n", hr);

			ResetEvent(g_hRunningEvent);

			return INJ_ERR_STRINGC_XXX_FAIL;
		}

		auto ren_ret = _wrename(OldFilePath, pData->szDllPath);
		if (ren_ret)
		{
			INIT_ERROR_DATA(error_data, (DWORD)errno);

			LOG(0, "_wrename failed: %08X\n", (DWORD)error_data.AdvErrorCode);

			return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_CANT_RENAME_FILE, error_data);
		}

		LOG(0, "Path of renamed dll: %ls\n", pData->szDllPath);
	}

	HANDLE hTargetProc = nullptr;
	if (pData->Flags & INJ_HIJACK_HANDLE)
	{
		if (pData->hHandleValue) 
		{
			LOG(0, "hHandleValue = %08X\n", pData->hHandleValue);
			
			hTargetProc = MPTR(pData->hHandleValue);
		}
		else
		{
			LOG(0, "Forwarding call to handle hijacking\n");
			
			return HijackHandle(pData, error_data);
		}
	}
	else
	{
		DWORD access_mask = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION;
		if (pData->Method == LAUNCH_METHOD::LM_NtCreateThreadEx)
		{
			access_mask |= PROCESS_CREATE_THREAD;
		}

		hTargetProc = OpenProcess(access_mask, FALSE, pData->ProcessID);
		if (!hTargetProc)
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(0, "OpenProcess failed: %08X\n", (DWORD)error_data.AdvErrorCode);

			return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_CANT_OPEN_PROCESS, error_data);
		}
	}

	DWORD handle_info = 0;
	if (!hTargetProc || !GetHandleInformation(hTargetProc, &handle_info))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(0, "Invalid process handle: %08X\n", (DWORD)error_data.AdvErrorCode);

		return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_INVALID_PROC_HANDLE, error_data);
	}

	LOG(0, "Attached to target process\n");

	wchar_t szExePath[MAX_PATH * 2]{ 0 };
	DWORD size_inout = sizeof(szExePath) / sizeof(szExePath[0]);
	if (!QueryFullProcessImageNameW(hTargetProc, NULL, szExePath, &size_inout))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(0, "QueryFullProcessImageNameW failed: %08X\n", (DWORD)error_data.AdvErrorCode);

		return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_CANT_GET_EXE_FILENAME, error_data);
	}

	wchar_t * pExeName = wcsrchr(szExePath, '\\');
	if (!pExeName)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "wcsrchr failed\n");

		return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_WCSRCHR_FAILED, error_data);
	}

	++pExeName;

	size_t length = 0;
	auto hr = StringCbLengthW(pExeName, sizeof(pData->szTargetProcessExeFileName), &length);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		LOG(0, "StringCbLengthW failed: %08X\n", (DWORD)hr);

		return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_STRINGC_XXX_FAIL, error_data);
	}

	if (length == 0)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Target process name length is 0\n");

		return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_STRINGC_XXX_FAIL, error_data);
	}

	hr = StringCbCopyW(pData->szTargetProcessExeFileName, sizeof(pData->szTargetProcessExeFileName), pExeName);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		LOG(0, "StringCbCopyW failed: %08X\n", (DWORD)hr);

		return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_STRINGC_XXX_FAIL, error_data);
	}

	LOG(0, "Target process name = %ls\n", pData->szTargetProcessExeFileName);

	LOG(0, "Validating specified file\n");

	DWORD FileErr = FILE_ERR_SUCCESS;
	bool native_target = true;
#ifdef _WIN64
	native_target = IsNativeProcess(hTargetProc);
	if (native_target)
	{
		FileErr = ValidateFile(szDllPath, IMAGE_FILE_MACHINE_AMD64);
	}
	else
	{
		FileErr = ValidateFile(szDllPath, IMAGE_FILE_MACHINE_I386);
	}
#else
	FileErr = ValidateFile(szDllPath, IMAGE_FILE_MACHINE_I386);
#endif

	if (FileErr != FILE_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, FileErr);

		LOG(0, "Invalid file specified\n");

		return InitErrorStruct(szDllPath, pData, native_target, INJ_ERR_PLATFORM_MISMATCH, error_data);
	}

	LOG(0, "File validated and prepared for injection:\n %ls\n", pData->szDllPath);
	
	HINSTANCE hOut = NULL;

#ifdef _WIN64
	if (native_target)
	{
		RetVal = InjectDLL(szDllPath, hTargetProc, pData->Mode, pData->Method, pData->Flags, hOut, pData->Timeout, error_data);
	}
	else
	{		
		RetVal = InjectDLL_WOW64(szDllPath, hTargetProc, pData->Mode, pData->Method, pData->Flags, hOut, pData->Timeout, error_data);
	}	
#else
	RetVal = InjectDLL(szDllPath, hTargetProc, pData->Mode, pData->Method, pData->Flags, hOut, pData->Timeout, error_data);
#endif

	LOG(0, "Injection finished\n");

	if (!(pData->Flags & INJ_HIJACK_HANDLE))
	{
		CloseHandle(hTargetProc);
	}
	
	pData->hDllOut = hOut;

	return InitErrorStruct(szDllPath, pData, native_target, RetVal, error_data);
}

DWORD HijackHandle(INJECTIONDATAW * pData, ERROR_DATA & error_data)
{
	LOG(1, "Begin HijackHandle\n");

	wchar_t * szDllPath = pData->szDllPath;

	DWORD access_mask = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;
	if (pData->Method == LAUNCH_METHOD::LM_NtCreateThreadEx)
	{
		access_mask |= PROCESS_CREATE_THREAD;
	}

	auto handles = FindProcessHandles(pData->ProcessID, access_mask);
	if (handles.empty())
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "No compatible handle found\n");

		return InitErrorStruct(szDllPath, pData, true, INJ_ERR_HIJACK_NO_HANDLES, error_data);
	}

	INJECTIONDATAW hijack_data{ 0 };
	hijack_data.Mode	= INJECTION_MODE::IM_LdrLoadDll;
	hijack_data.Method	= LAUNCH_METHOD::LM_NtCreateThreadEx;
	hijack_data.Timeout = pData->Timeout;
	hijack_data.GenerateErrorLog = pData->GenerateErrorLog;

	HRESULT hr = StringCbCopyW(hijack_data.szDllPath, sizeof(hijack_data.szDllPath), g_RootPathW.c_str());
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		LOG(1, "StringCbCopyW failed: %08X\n", error_data.AdvErrorCode);

		return InitErrorStruct(szDllPath, pData, true, INJ_ERR_STRINGC_XXX_FAIL, error_data);
	}

	hr = StringCbCatW(hijack_data.szDllPath, sizeof(hijack_data.szDllPath), GH_INJ_MOD_NAMEW);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		LOG(1, "StringCbCatW failed: %08X\n", error_data.AdvErrorCode);

		return InitErrorStruct(szDllPath, pData, true, INJ_ERR_STRINGC_XXX_FAIL, error_data);
	}

	DWORD OrigFlags	= pData->Flags;
	if (pData->Flags & INJ_LOAD_DLL_COPY)
	{
		pData->Flags ^= INJ_LOAD_DLL_COPY;
	}

	if (pData->Flags & INJ_SCRAMBLE_DLL_NAME)
	{
		pData->Flags ^= INJ_SCRAMBLE_DLL_NAME;
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

		pData->hHandleValue = i.hValue;
		if (!WriteProcessMemory(hHijackProc, pArg, pData, sizeof(INJECTIONDATAW), nullptr))
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

		pData->hHandleValue = 0;

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
		DWORD remote_ret = StartRoutine(hHijackProc, pRemoteInjectW, pArg, LAUNCH_METHOD::LM_NtCreateThreadEx, NULL, hijack_ret, pData->Timeout, error_data);
				
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

		LOG(1, "Hijack injection succeeded\nImagebase = %p\n", (void *)data_out.hDllOut);

		pData->hDllOut = data_out.hDllOut;

		LastErrCode = INJ_ERR_SUCCESS;

		break;
	}

	pData->Flags = OrigFlags;

	LOG(1, "End HijackHandle\n");

	return InitErrorStruct(szDllPath, pData, true, LastErrCode, error_data);
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

	return StringCbCopyA(out, cb_size, GH_INJ_VERSIONA);
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

	return StringCbCopyW(out, cb_size, GH_INJ_VERSIONW);
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