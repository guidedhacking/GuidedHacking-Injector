#include "pch.h"

#include "Injection.h"

DWORD InitErrorStruct(const wchar_t * szDllPath, INJECTIONDATAW * pData, int bNative, DWORD ErrorCode, ERROR_DATA error_data);

DWORD InjectDLL(const wchar_t * szDllFile, HANDLE hTargetProc, INJECTION_MODE im, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, ERROR_DATA & error_data);

DWORD HijackHandle(INJECTIONDATAW * pData, ERROR_DATA & error_data);

DWORD InitErrorStruct(const wchar_t * szDllPath, INJECTIONDATAW * pData, int bNative, DWORD ErrorCode, ERROR_DATA error_data)
{
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

		ErrorLog(&info);
	}

	return ErrorCode;
}

DWORD __stdcall InjectA(INJECTIONDATAA * pData)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	LOG("InjectA called with pData = %p\n", pData);

	ERROR_DATA error_data{ 0 };

	if (!pData)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return InitErrorStruct(nullptr, ReCa<INJECTIONDATAW*>(pData), -1, INJ_ERR_NO_DATA, error_data);
	}
	
	if (!pData->szDllPath)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return InitErrorStruct(nullptr, ReCa<INJECTIONDATAW*>(pData), -1, INJ_ERR_INVALID_FILEPATH, error_data);
	}
	
	INJECTIONDATAW data{ 0 };
	size_t len_out = 0;
	size_t max_len = sizeof(data.szDllPath) / sizeof(wchar_t);
	HRESULT hr = StringCchLengthA(pData->szDllPath, max_len, &len_out);
	if (FAILED(hr) || !len_out)
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		return InitErrorStruct(nullptr, ReCa<INJECTIONDATAW*>(pData), -1, INJ_ERR_STRINGC_XXX_FAIL, error_data);
	}

	auto err = mbstowcs_s(&len_out, data.szDllPath, max_len, pData->szDllPath, max_len);
	if (err)
	{
		INIT_ERROR_DATA(error_data, (DWORD)err);

		return InitErrorStruct(nullptr, ReCa<INJECTIONDATAW*>(pData), -1, INJ_ERR_STR_CONVERSION_TO_W_FAILED, error_data);
	}

	data.ProcessID			= pData->ProcessID;
	data.Mode				= pData->Mode;
	data.Method				= pData->Method;
	data.Flags				= pData->Flags;
	data.hHandleValue		= pData->hHandleValue;
	data.GenerateErrorLog	= pData->GenerateErrorLog;

	LOG("Forwarding call to InjectW\n");

	DWORD Ret = InjectW(&data);
	pData->hDllOut = data.hDllOut;

	return Ret;
}

DWORD __stdcall InjectW(INJECTIONDATAW * pData)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	LOG("InjectW called with pData = %p\n", pData);
	
	ERROR_DATA error_data{ 0 };
	DWORD RetVal = INJ_ERR_SUCCESS;

	if (!pData)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return InitErrorStruct(nullptr, pData, -1, INJ_ERR_NO_DATA, error_data);
	}

	RetVal = ResolveImports(error_data);
	if (RetVal != INJ_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return InitErrorStruct(nullptr, pData, -1, RetVal, error_data);
	}
		
	if (!pData->szDllPath)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return InitErrorStruct(nullptr, pData, -1, INJ_ERR_INVALID_FILEPATH, error_data);
	}

	const wchar_t * szDllPath = pData->szDllPath;

	if (!FileExists(szDllPath))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_FILE_DOESNT_EXIST, error_data);
	}

	if (!pData->ProcessID)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_INVALID_PID, error_data);
	}

	if (pData->Flags & INJ_LOAD_DLL_COPY)
	{
		size_t len_out = 0;
		HRESULT hr = StringCchLengthW(pData->szDllPath, MAXPATH_IN_TCHAR, &len_out);
		if (FAILED(hr) || !len_out)
		{
			INIT_ERROR_DATA(error_data, (DWORD)hr);

			return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_STRINGC_XXX_FAIL, error_data);
		}

		const wchar_t * pFileName = pData->szDllPath;
		pFileName += len_out;
		while (*(--pFileName - 1) != '\\');

		wchar_t new_path[MAXPATH_IN_TCHAR]{ 0 };
		if (!GetTempPathW(MAXPATH_IN_TCHAR, new_path))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_CANT_GET_TEMP_DIR, error_data);
		}

		hr = StringCchCatW(new_path, MAXPATH_IN_TCHAR, pFileName);
		if (FAILED(hr))
		{
			INIT_ERROR_DATA(error_data, (DWORD)hr);

			return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_STRINGC_XXX_FAIL, error_data);
		}

		if (!CopyFileW(pData->szDllPath, new_path, FALSE))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_CANT_COPY_FILE, error_data);
		}

		hr = StringCbCopyW(pData->szDllPath, sizeof(pData->szDllPath), new_path);
		if (FAILED(hr))
		{
			INIT_ERROR_DATA(error_data, (DWORD)hr);

			return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_STRINGC_XXX_FAIL, error_data);
		}

		LOG("Path of dll copy: %ls\n", pData->szDllPath);
	}

	if (pData->Flags & INJ_SCRAMBLE_DLL_NAME)
	{
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

			return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_STRINGC_XXX_FAIL, error_data);
		}

		wchar_t * pFileName = wcsrchr(pData->szDllPath, '\\') + 1;
		memcpy(pFileName, new_name, sizeof(new_name));

		auto ren_ret = _wrename(OldFilePath, pData->szDllPath);
		if (ren_ret)
		{
			INIT_ERROR_DATA(error_data, (DWORD)errno);

			return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_CANT_RENAME_FILE, error_data);
		}

		LOG("Path of renamed dll: %ls\n", pData->szDllPath);
	}

	HANDLE hTargetProc = nullptr;
	if (pData->Flags & INJ_HIJACK_HANDLE)
	{
		if (pData->hHandleValue) 
		{
			hTargetProc = MPTR(pData->hHandleValue);
		}
		else
		{
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

			return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_CANT_OPEN_PROCESS, error_data);
		}
	}

	DWORD handle_info = 0;
	if (!hTargetProc || !GetHandleInformation(hTargetProc, &handle_info))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_INVALID_PROC_HANDLE, error_data);
	}

	if (!K32GetModuleBaseNameW(hTargetProc, NULL, pData->szTargetProcessExeFileName, sizeof(pData->szTargetProcessExeFileName) / sizeof(pData->szTargetProcessExeFileName[0])))
	{
		INIT_ERROR_DATA(error_data, GetLastError());
		
		return InitErrorStruct(szDllPath, pData, -1, INJ_ERR_CANT_GET_EXE_FILENAME, error_data);
	}

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

	if (FileErr)
	{
		INIT_ERROR_DATA(error_data, FileErr);

		return InitErrorStruct(szDllPath, pData, native_target, INJ_ERR_PLATFORM_MISMATCH, error_data);
	}

	LOG("File validated and prepared for injection:\n%ls\n", pData->szDllPath);
	
	HINSTANCE hOut	= NULL;

#ifdef _WIN64
	if (native_target)
	{
		RetVal = InjectDLL(szDllPath, hTargetProc, pData->Mode, pData->Method, pData->Flags, hOut, error_data);
	}
	else
	{		
		RetVal = InjectDLL_WOW64(szDllPath, hTargetProc, pData->Mode, pData->Method, pData->Flags, hOut, error_data);
	}	
#else
	RetVal = InjectDLL(szDllPath, hTargetProc, pData->Mode, pData->Method, pData->Flags, hOut, error_data);
#endif

	LOG("Injection finished\n");

	if (!(pData->Flags & INJ_HIJACK_HANDLE))
	{
		CloseHandle(hTargetProc);
	}
	
	pData->hDllOut = hOut;

	return InitErrorStruct(szDllPath, pData, native_target, RetVal, error_data);
}

DWORD HijackHandle(INJECTIONDATAW * pData, ERROR_DATA & error_data)
{
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

		return InitErrorStruct(szDllPath, pData, true, INJ_ERR_HIJACK_NO_HANDLES, error_data);
	}

	INJECTIONDATAW hijack_data{ 0 };
	hijack_data.Mode	= INJECTION_MODE::IM_LdrLoadDll;
	hijack_data.Method	= LAUNCH_METHOD::LM_NtCreateThreadEx;
	hijack_data.GenerateErrorLog = pData->GenerateErrorLog;

	HRESULT hr = StringCbCopyW(hijack_data.szDllPath, sizeof(hijack_data.szDllPath), g_RootPathW.c_str());
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

		return InitErrorStruct(szDllPath, pData, true, INJ_ERR_STRINGC_XXX_FAIL, error_data);
	}

	hr = StringCbCatW(hijack_data.szDllPath, sizeof(hijack_data.szDllPath), GH_INJ_MOD_NAMEW);
	if (FAILED(hr))
	{
		INIT_ERROR_DATA(error_data, (DWORD)hr);

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
	for (auto i : handles)
	{
		hHijackProc = OpenProcess(access_mask | PROCESS_CREATE_THREAD, FALSE, i.OwnerPID);
		if (!hHijackProc)
		{
			LastErrCode = INJ_ERR_CANT_OPEN_PROCESS;
			INIT_ERROR_DATA(error_data, GetLastError());

			continue;
		}
					
		if (!IsElevatedProcess(hHijackProc) || !IsNativeProcess(hHijackProc))
		{
			LastErrCode = INJ_ERR_HIJACK_NO_NATIVE_HANDLE;
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			CloseHandle(hHijackProc);
			
			continue;
		}

		hijack_data.ProcessID = i.OwnerPID;
		DWORD inj_ret = InjectW(&hijack_data);

		if (inj_ret || !hijack_data.hDllOut)
		{
			LastErrCode = INJ_ERR_HIJACK_INJ_FAILED;
			INIT_ERROR_DATA(error_data, inj_ret);

			CloseHandle(hHijackProc);
			
			continue;
		}

		HINSTANCE hInjectionModuleEx = hijack_data.hDllOut;
		f_Routine pRemoteInjectW = ReCa<f_Routine>(ReCa<UINT_PTR>(InjectW) - ReCa<UINT_PTR>(g_hInjMod) + ReCa<UINT_PTR>(hInjectionModuleEx));
				
		void * pArg = VirtualAllocEx(hHijackProc, nullptr, sizeof(INJECTIONDATAW), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pArg)
		{
			LastErrCode = INJ_ERR_HIJACK_OUT_OF_MEMORY_EXT;
			INIT_ERROR_DATA(error_data, GetLastError());

			EjectDll(hHijackProc, hInjectionModuleEx);

			CloseHandle(hHijackProc);
			
			continue;
		}

		pData->hHandleValue = i.hValue;
		if (!WriteProcessMemory(hHijackProc, pArg, pData, sizeof(INJECTIONDATAW), nullptr))
		{
			LastErrCode = INJ_ERR_HIJACK_WPM_FAIL;
			INIT_ERROR_DATA(error_data, GetLastError());

			VirtualFreeEx(hHijackProc, pArg, 0, MEM_RELEASE);
			EjectDll(hHijackProc, hInjectionModuleEx);

			CloseHandle(hHijackProc);
			
			continue;
		}

		pData->hHandleValue = 0;

		DWORD hijack_ret = INJ_ERR_SUCCESS;
		DWORD remote_ret = StartRoutine(hHijackProc, pRemoteInjectW, pArg, LAUNCH_METHOD::LM_NtCreateThreadEx, false, hijack_ret, error_data);
		
		INJECTIONDATAW data_out{ 0 };
		ReadProcessMemory(hHijackProc, pArg, &data_out, sizeof(INJECTIONDATAW), nullptr);
		
		VirtualFreeEx(hHijackProc, pArg, 0, MEM_RELEASE);
		EjectDll(hHijackProc, hInjectionModuleEx);

		CloseHandle(hHijackProc);

		if (remote_ret != SR_ERR_SUCCESS)
		{
			LastErrCode = remote_ret;

			continue;
		}

		if (hijack_ret != INJ_ERR_SUCCESS || !data_out.hDllOut)
		{
			LastErrCode = INJ_ERR_HIJACK_REMOTE_INJ_FAIL;
			INIT_ERROR_DATA(error_data, hijack_ret);

			continue;
		}

		pData->hDllOut = data_out.hDllOut;

		LastErrCode = INJ_ERR_SUCCESS;

		break;
	}

	pData->Flags = OrigFlags;

	return InitErrorStruct(szDllPath, pData, true, LastErrCode, error_data);
}

HRESULT __stdcall GetVersionA(char * out, size_t cb_size)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	if (!out)
	{
		return E_INVALIDARG;
	}

	if (sizeof(GH_INJ_VERSIONA) > cb_size)
	{
		return TYPE_E_BUFFERTOOSMALL;
	}

	return StringCbCopyA(out, cb_size, GH_INJ_VERSIONA);
}

HRESULT __stdcall GetVersionW(wchar_t * out, size_t cb_size)
{
#pragma EXPORT_FUNCTION(__FUNCTION__, __FUNCDNAME__)

	if (!out)
	{
		return E_INVALIDARG;
	}

	if (sizeof(GH_INJ_VERSIONA) > cb_size)
	{
		return TYPE_E_BUFFERTOOSMALL;
	}

	return StringCbCopyW(out, cb_size, GH_INJ_VERSIONW);
}