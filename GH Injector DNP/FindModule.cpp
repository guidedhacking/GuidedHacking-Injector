/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

#include "pch.h"

#include "FindModule.h"

void StdWStringToLower(std::wstring & String)
{
	std::transform(String.begin(), String.end(), String.begin(),
		[](wchar_t c)
		{
			return std::towlower(c);
		}
	);
}

DWORD FindModuleW(const std::wstring & ModulePath, HINSTANCE & hOut)
{
	//Gotta VirtualQuery this shit because .NET files aren't linked to the PEB so normal methods like TH32 snapshots or GetModuleHandle don't work

	auto ModuleNamePos = ModulePath.find_last_of('\\');
	if (ModuleNamePos == std::wstring::npos)
	{
		CONSOLE_LOG("ModulePath is invalid\n");
		
		return ERROR_INVALID_PARAMETER;
	}

	auto ModuleName			= ModulePath.substr(ModuleNamePos + 1);
	auto hCurrentProcess	= GetCurrentProcess();

	StdWStringToLower(ModuleName);

	MEMORY_BASIC_INFORMATION MBI{ 0 };
	wchar_t NameBuffer[MAX_PATH * 2]{ 0 };

	while (VirtualQuery(MBI.BaseAddress, &MBI, sizeof(MBI)))
	{
		if ((MBI.Type == MEM_IMAGE) && (MBI.State & MEM_COMMIT))
		{
			if (K32GetMappedFileNameW(hCurrentProcess, MBI.BaseAddress, NameBuffer, sizeof(NameBuffer) / sizeof(wchar_t)))
			{
				auto FilePath = std::wstring(NameBuffer);
				auto FileNamePos = FilePath.find_last_of('\\');

				if (FileNamePos != std::wstring::npos)
				{
					auto FileName = FilePath.substr(FileNamePos + 1);
					StdWStringToLower(FileName);

					if (FileName.compare(ModuleName) == 0)
					{
						hOut = reinterpret_cast<HINSTANCE>(MBI.BaseAddress);

						return ERROR_SUCCESS;
					}
					else
					{
						CONSOLE_LOG("%ls - %ls\n", FileName.c_str(), ModuleName.c_str());

					}
				}
			}
		}

		MBI.BaseAddress = reinterpret_cast<BYTE *>(MBI.BaseAddress) + MBI.RegionSize;
	}

	return ERROR_MOD_NOT_FOUND;
}