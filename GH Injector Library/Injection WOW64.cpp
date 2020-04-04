#include "pch.h"

#ifdef _WIN64

#include "Injection.h"
#pragma comment (lib, "Psapi.lib")

DWORD Cloaking_WOW64(HANDLE hTargetProc, DWORD Flags, HINSTANCE hMod, ERROR_DATA & error_data);

DWORD InjectDLL_WOW64(const wchar_t * szDllFile, HANDLE hTargetProc, INJECTION_MODE im, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, ERROR_DATA & error_data)
{
	DWORD Ret = 0;

	switch (im)
	{
		case INJECTION_MODE::IM_LoadLibraryExW:
			Ret = _LoadLibrary_WOW64(szDllFile, hTargetProc, Method, Flags, hOut, error_data);
			break;

		case INJECTION_MODE::IM_LdrLoadDll:
			Ret = _LdrLoadDll_WOW64(szDllFile, hTargetProc, Method, Flags, hOut, error_data);
			break;

		case INJECTION_MODE::IM_LdrpLoadDll:
			Ret = _LdrpLoadDll_WOW64(szDllFile, hTargetProc, Method, Flags, hOut, error_data);
			break;

		case INJECTION_MODE::IM_ManualMap:
			Ret = _ManualMap_WOW64(szDllFile, hTargetProc, Method, Flags, hOut, error_data);
			break;

		default:
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			Ret = INJ_ERR_INVALID_INJ_METHOD;
			break;
	}

	if (Ret != INJ_ERR_SUCCESS)
	{
		return Ret;
	}

	if (!hOut)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return INJ_ERR_REMOTE_CODE_FAILED;
	}

	if (im != INJECTION_MODE::IM_ManualMap)
	{
		Ret = Cloaking_WOW64(hTargetProc, Flags, hOut, error_data);
	}
	
	return Ret;
}

DWORD Cloaking_WOW64(HANDLE hTargetProc, DWORD Flags, HINSTANCE hMod, ERROR_DATA & error_data)
{
	if (!Flags) 
	{
		return INJ_ERR_SUCCESS;
	}

	if (Flags & INJ_ERASE_HEADER)
	{
		BYTE Buffer[0x1000]{ 0 };
		if (!WriteProcessMemory(hTargetProc, hMod, Buffer, 0x1000, nullptr))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			return INJ_ERR_WPM_FAIL;
		}
	}
	else if (Flags & INJ_FAKE_HEADER)
	{
		void * pK32 = ReCa<void*>(GetModuleHandleEx_WOW64(hTargetProc, TEXT("kernel32.dll")));

		BYTE buffer[0x1000];
		if (!ReadProcessMemory(hTargetProc, pK32, buffer, 0x1000, nullptr))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			return INJ_ERR_RPM_FAIL;
		}
	
		if (!WriteProcessMemory(hTargetProc, hMod, buffer, 0x1000, nullptr))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			return INJ_ERR_WPM_FAIL;
		}
	}

	if (Flags & INJ_UNLINK_FROM_PEB)
	{
		ProcessInfo PI;
		PI.SetProcess(hTargetProc);

		LDR_DATA_TABLE_ENTRY32 * pEntry = PI.GetLdrEntry_WOW64(hMod);
		if (!pEntry)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			return INJ_ERR_CANT_FIND_MOD_PEB;
		}

		LDR_DATA_TABLE_ENTRY32 Entry{ 0 };
		if (!ReadProcessMemory(hTargetProc, pEntry, &Entry, sizeof(Entry), nullptr))
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			return INJ_ERR_CANT_ACCESS_PEB_LDR;
		}
		
		auto Unlink = [=](LIST_ENTRY32 entry)
		{
			LIST_ENTRY32 list;
			if (ReadProcessMemory(hTargetProc, MPTR(entry.Flink), &list, sizeof(LIST_ENTRY32), nullptr))
			{
				list.Blink = entry.Blink;
				WriteProcessMemory(hTargetProc, MPTR(entry.Flink), &list, sizeof(LIST_ENTRY32), nullptr);
			}

			if (ReadProcessMemory(hTargetProc, MPTR(entry.Blink), &list, sizeof(LIST_ENTRY32), nullptr))
			{
				list.Flink = entry.Flink;
				WriteProcessMemory(hTargetProc, MPTR(entry.Blink), &list, sizeof(LIST_ENTRY32), nullptr);
			}
		};
		
		Unlink(Entry.InLoadOrderLinks);
		Unlink(Entry.InMemoryOrderLinks);
		Unlink(Entry.InInitializationOrderLinks);
		Unlink(Entry.HashLinks);

		WORD MaxLength_Full = Entry.FullDllName.MaxLength;
		WORD MaxLength_Base = Entry.BaseDllName.MaxLength;
		char * Buffer_Full = new char[MaxLength_Full];
		char * Buffer_Base = new char[MaxLength_Base];
		memset(Buffer_Full, 0, MaxLength_Full);
		memset(Buffer_Base, 0, MaxLength_Base);
		WriteProcessMemory(hTargetProc, MPTR(Entry.FullDllName.szBuffer), Buffer_Full, MaxLength_Full, nullptr);
		WriteProcessMemory(hTargetProc, MPTR(Entry.BaseDllName.szBuffer), Buffer_Base, MaxLength_Base, nullptr);
		delete[] Buffer_Full;
		delete[] Buffer_Base;

		LDR_DATA_TABLE_ENTRY32 entry_new{ 0 };
		WriteProcessMemory(hTargetProc, pEntry, &entry_new, sizeof(entry_new), nullptr);

		//todo LdrpModuleBaseAddressIndex (cancer)
	}
	
	return INJ_ERR_SUCCESS;
}

#endif