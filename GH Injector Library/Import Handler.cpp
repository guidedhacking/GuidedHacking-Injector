#include "pch.h"

#include "Import Handler.h"

#ifdef UNICODE
#undef MODULEENTRY32
#undef Module32First
#undef Module32Next
#endif

#undef GetModuleHandleEx

HINSTANCE GetModuleHandleEx(HANDLE hTargetProc, const TCHAR * szModuleName)
{
#ifdef UNICODE
	return GetModuleHandleExW(hTargetProc, szModuleName);
#else
	return GetModuleHandleExA(hTargetProc, szModuleName);
#endif
}

HINSTANCE GetModuleHandleExA(HANDLE hTargetProc, const char * szModuleName)
{
	MODULEENTRY32 ME32{ 0 };
	ME32.dwSize = sizeof(ME32);
	
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hTargetProc));
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		while (GetLastError() == ERROR_BAD_LENGTH)
		{
			hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hTargetProc));
		
			if (hSnap != INVALID_HANDLE_VALUE)
			{
				break;
			}
		}
	}
	
	if (hSnap == INVALID_HANDLE_VALUE || !hSnap)
	{
		return NULL;
	}
	
	BOOL bRet = Module32First(hSnap, &ME32);
	do
	{
		if (!_stricmp(ME32.szModule, szModuleName))
		{
			break;
		}

		bRet = Module32Next(hSnap, &ME32);
	} 
	while (bRet);
	
	CloseHandle(hSnap);

	if (!bRet)
	{
		return NULL;
	}

	return ME32.hModule;
}

HINSTANCE GetModuleHandleExW(HANDLE hTargetProc, const wchar_t * szModuleName)
{
	MODULEENTRY32W ME32{ 0 };
	ME32.dwSize = sizeof(ME32);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hTargetProc));
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		while (GetLastError() == ERROR_BAD_LENGTH)
		{
			hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hTargetProc));

			if (hSnap != INVALID_HANDLE_VALUE)
			{
				break;
			}
		}
	}

	if (hSnap == INVALID_HANDLE_VALUE || !hSnap)
	{
		return NULL;
	}

	BOOL bRet = Module32FirstW(hSnap, &ME32);
	do
	{
		if (!_wcsicmp(ME32.szModule, szModuleName))
		{
			break;
		}

		bRet = Module32NextW(hSnap, &ME32);
	} while (bRet);

	CloseHandle(hSnap);

	if (!bRet)
	{
		return NULL;
	}

	return ME32.hModule;
}

bool GetProcAddressEx(HANDLE hTargetProc, const TCHAR * szModuleName, const char * szProcName, void * &pOut)
{
	return GetProcAddressEx(hTargetProc, GetModuleHandleEx(hTargetProc, szModuleName), szProcName, pOut);
}

bool GetProcAddressEx(HANDLE hTargetProc, HINSTANCE hModule, const char * szProcName, void * &pOut)
{
	BYTE * modBase = ReCa<BYTE*>(hModule);

	if (!modBase)
	{
		return false;
	}

	BYTE * pe_header = new BYTE[0x1000];
	if (!pe_header)
	{
		return false;
	}

	if (!ReadProcessMemory(hTargetProc, modBase, pe_header, 0x1000, nullptr))
	{
		delete[] pe_header;

		return false;
	}

	auto * pNT			= ReCa<IMAGE_NT_HEADERS*>(pe_header + ReCa<IMAGE_DOS_HEADER*>(pe_header)->e_lfanew);
	auto * pExportEntry	= &pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	auto ExportSize		= pExportEntry->Size;
	auto ExportDirRVA	= pExportEntry->VirtualAddress;
	
	if (!ExportSize)
	{
		delete[] pe_header;

		return false;
	}

	BYTE * export_data = new BYTE[ExportSize];
	if (!export_data)
	{
		delete[] pe_header;

		return false;
	}

	if (!ReadProcessMemory(hTargetProc, modBase + ExportDirRVA, export_data, ExportSize, nullptr))
	{
		delete[] export_data;
		delete[] pe_header;

		return false;
	}
		
	BYTE * localBase	= export_data - ExportDirRVA;
	auto pExportDir		= ReCa<IMAGE_EXPORT_DIRECTORY*>(export_data);

	auto Forward = [&](DWORD FuncRVA) -> bool
	{
		char pFullExport[MAX_PATH]{ 0 };
		size_t len_out = 0;

		HRESULT hr = StringCchLengthA(ReCa<char*>(localBase + FuncRVA), sizeof(pFullExport), &len_out);
		if (FAILED(hr) || !len_out) 
		{
			return false;
		}

		memcpy(pFullExport, ReCa<char*>(localBase + FuncRVA), len_out);

		char * pFuncName = strchr(pFullExport, '.');
		*(pFuncName++) = '\0';
		if (*pFuncName == '#')
		{
			pFuncName = ReCa<char *>(LOWORD(atoi(++pFuncName)));
		}

#ifdef UNICODE

		wchar_t ModNameW[MAX_PATH]{ 0 };
		size_t SizeOut = 0;

		if (mbstowcs_s(&SizeOut, ModNameW, pFullExport, MAX_PATH))
		{
			return GetProcAddressEx(hTargetProc, ModNameW, pFuncName, pOut);
		}
		else
		{
			return false;
		}

#else

		return GetProcAddressEx(hTargetProc, pFullExport, pFuncName, pOut);

#endif
	};

	if ((ReCa<ULONG_PTR>(szProcName) & 0xFFFFFF) <= MAXWORD)
	{
		WORD Base		= LOWORD(pExportDir->Base - 1);
		WORD Ordinal	= LOWORD(szProcName) - Base;
		DWORD FuncRVA	= ReCa<DWORD*>(localBase + pExportDir->AddressOfFunctions)[Ordinal];
		
		delete[] export_data;
		delete[] pe_header;

		if (FuncRVA >= ExportDirRVA && FuncRVA < ExportDirRVA + ExportSize)
		{
			return Forward(FuncRVA);
		}

		return modBase + FuncRVA;
	}

	DWORD max		= pExportDir->NumberOfNames - 1;
	DWORD min		= 0;
	DWORD FuncRVA	= 0;

	while (min <= max)
	{
		DWORD mid = (min + max) / 2;

		DWORD CurrNameRVA	= ReCa<DWORD*>(localBase + pExportDir->AddressOfNames)[mid];
		char * szName		= ReCa<char*>(localBase + CurrNameRVA);

		int cmp = strcmp(szName, szProcName);
		if (cmp < 0)
		{
			min = mid + 1;
		}
		else if (cmp > 0)
		{
			max = mid - 1;
		}
		else
		{
			WORD Ordinal = ReCa<WORD*>(localBase + pExportDir->AddressOfNameOrdinals)[mid];
			FuncRVA = ReCa<DWORD*>(localBase + pExportDir->AddressOfFunctions)[Ordinal];

			break;
		}
	}

	delete[] export_data;
	delete[] pe_header;

	if (!FuncRVA)
	{
		return false;
	}
	
	if (FuncRVA >= ExportDirRVA && FuncRVA < ExportDirRVA + ExportSize)
	{
		return Forward(FuncRVA);
	}
	
	pOut = modBase + FuncRVA;

	return true;
}