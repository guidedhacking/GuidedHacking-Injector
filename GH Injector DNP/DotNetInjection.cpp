/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

#include "pch.h"

#include "DotNetInjection.h"
#include "FindModule.h"

HRESULT LoadDotNetDll(const std::wstring & FilePath, const std::wstring & Version, const std::wstring & TypeName, const std::wstring & MethodName, const std::wstring & Argument, HINSTANCE & ModuleBase, DWORD & ReturnValue);
void Log(const std::wstring & path, DWORD error, HINSTANCE base);

DWORD __stdcall LoadDotNetBinary(void * pArg)
{
	UNREFERENCED_PARAMETER(pArg);

	if (!g_hModuleBase)
	{
		CONSOLE_LOG("Invalid modules base\n");

		return 0;
	}

	wchar_t szInfoPath[MAX_PATH * 2]{ 0 };
	size_t max_size = sizeof(szInfoPath) / sizeof(wchar_t);

	DWORD dwRet = GetModuleFileNameW(g_hModuleBase, szInfoPath, (DWORD)max_size);
	if (!dwRet || GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		CONSOLE_LOG("GetModuleFileNameW failed: %08X\n", dwRet);

		return 0;
	}

	std::wstring InfoPath = szInfoPath;
	auto pos = InfoPath.find_last_of('\\');
	if (pos == std::wstring::npos)
	{
		CONSOLE_LOG("Invalid InfoPath\n");

		return 0;
	}

	InfoPath.erase(pos, InfoPath.back());
	InfoPath += FILENAME;

	std::wifstream File(InfoPath);
	if (!File.good())
	{
		CONSOLE_LOG("Failed to open InfoPath\n");

		File.close();

		DeleteFileW(InfoPath.c_str());

		Log(InfoPath, DNP_ERR_CANT_OPEN_FILE, NULL);

		return 0;
	}

	std::wstringstream info_raw;
	info_raw << File.rdbuf();

	File.close();

	DeleteFileW(InfoPath.c_str());

	std::wstring info = info_raw.str();
	std::vector<std::wstring> dot_net_data;

	size_t current_position = info.find('\n');
	while (current_position != std::wstring::npos)
	{
		dot_net_data.push_back(info.substr(0, current_position));
		info.erase(0, current_position + sizeof('\n'));

		current_position = info.find('\n');
	}

	dot_net_data.push_back(info);

	if (dot_net_data.size() < 6)
	{
		CONSOLE_LOG("Invalid info: %d arguments provided (6 expected)\n", (DWORD)dot_net_data.size());

		Log(InfoPath, DNP_ERR_INVALID_DATA, NULL);

		return 0;
	}

	auto & dll_path			= dot_net_data[0];
	auto & dot_net_version	= dot_net_data[1];
	auto & info_typename	= dot_net_data[2].append(std::wstring(L".").append(dot_net_data[3]));
	auto & info_method		= dot_net_data[4];
	auto & info_argument	= dot_net_data[5];

	DWORD		ReturnValue = 0;
	HINSTANCE	ModuleBase	= NULL;
	auto hRet = LoadDotNetDll(dll_path, dot_net_version, info_typename, info_method, info_argument, ModuleBase, ReturnValue);

	if (hRet == S_OK)
	{
		Log(InfoPath, DNP_ERR_SUCCESS, ModuleBase);
	}
	else
	{
		Log(InfoPath, (DWORD)hRet, (HINSTANCE)DNP_ERR_HRESULT);
	}

	return 0;
}

HRESULT LoadDotNetDll(const std::wstring & FilePath, const std::wstring & Version, const std::wstring & TypeName, const std::wstring & MethodName, const std::wstring & Argument, HINSTANCE & ModuleBase, DWORD & ReturnValue)
{
	//I stole the following code years ago somewhere and am unable to fine the original source, I'm sorry :c

	ICLRMetaHost	* MetaHost		= nullptr;
	IEnumUnknown	* RuntimeEnum	= nullptr;
	ICLRRuntimeInfo * RuntimeInfo	= nullptr;
	ICLRRuntimeHost * RuntimeHost	= nullptr;

	bool AlreadyLoaded = false;

	HRESULT hRet = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, reinterpret_cast<void **>(&MetaHost));
	if (hRet != S_OK)
	{
		CONSOLE_LOG("CLRCreateInstance failed: %08X\n", hRet);

		return hRet;
	}

	hRet = MetaHost->EnumerateLoadedRuntimes(GetCurrentProcess(), &RuntimeEnum);
	if (hRet == S_OK)
	{
		ICLRRuntimeInfo * current_runtime = nullptr;

		ULONG count = 0;
		wchar_t current_runtime_version[MAX_PATH]{ 0 };

		auto enum_ret = RuntimeEnum->Next(1, reinterpret_cast<IUnknown **>(&current_runtime), &count);
		while (enum_ret == S_OK)
		{
			DWORD size = MAX_PATH;

			hRet = current_runtime->GetVersionString(current_runtime_version, &size);
			if (hRet == S_OK)
			{
				if (!Version.compare(current_runtime_version))
				{
					RuntimeInfo = current_runtime;
					AlreadyLoaded = true;

					CONSOLE_LOG("Runtime version %ls already loaded\n", Version.c_str());

					break;
				}
			}

			current_runtime->Release();

			enum_ret = RuntimeEnum->Next(1, reinterpret_cast<IUnknown **>(&current_runtime), &count);
		}

		RuntimeEnum->Release();
	}

	if (!AlreadyLoaded)
	{
		hRet = MetaHost->GetRuntime(Version.c_str(), IID_ICLRRuntimeInfo, reinterpret_cast<void **>(&RuntimeInfo));
		if (hRet != S_OK)
		{
			CONSOLE_LOG("ICLRMetaHost::GetRuntime failed: %08X\n", hRet);

			MetaHost->Release();

			return hRet;
		}
	}

	hRet = RuntimeInfo->GetInterface(CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost, reinterpret_cast<void **>(&RuntimeHost));
	if (hRet != S_OK)
	{
		CONSOLE_LOG("ICLRRuntimeInfo::GetInterface failed: %08X\n", hRet);

		RuntimeInfo->Release();
		MetaHost->Release();

		return hRet;
	}
	
	if (!AlreadyLoaded)
	{
		hRet = RuntimeHost->Start();
		if (hRet != S_OK)
		{
			CONSOLE_LOG("ICLRRuntimeHost::Start failed: %08X\n", hRet);

			RuntimeHost->Release();
			RuntimeInfo->Release();
			MetaHost->Release();

			return hRet;
		}
	}	

	hRet = RuntimeHost->ExecuteInDefaultAppDomain(FilePath.c_str(), TypeName.c_str(), MethodName.c_str(), Argument.c_str(), &ReturnValue);
	if (hRet == S_OK)
	{
		DWORD dwRet = FindModuleW(FilePath, ModuleBase);
		if (dwRet != ERROR_SUCCESS)
		{
			CONSOLE_LOG("FindModuleW failed: %08X\n", dwRet);

			hRet = (HRESULT)dwRet;
		}
	}
	else
	{
		CONSOLE_LOG("ICLRRuntimeHost::ExecuteInDefaultAppDomain failed: %08X\n", hRet);
	}

	RuntimeHost->Release();
	RuntimeInfo->Release();
	MetaHost->Release();

	return hRet;
}

void Log(const std::wstring & path, DWORD error, HINSTANCE base)
{
	std::wofstream File(path);
	if (!File.good())
	{
		return;
	}

	File << std::hex << base << std::endl;
	File << std::hex << error << std::endl;

	File.close();
}