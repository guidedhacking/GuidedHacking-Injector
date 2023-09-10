/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

#pragma once

#include "Injection.h"

#define BASE_ALIGNMENT		0x10

#define EH_MAGIC_NUMBER1        0x19930520    
#define EH_PURE_MAGIC_NUMBER1   0x01994000
#define EH_EXCEPTION_NUMBER     ('msc' | 0xE0000000)

#define VEHDATASIG_32 0xFACEB00C
#define VEHDATASIG_64 0xB16B00B500B16A33

#ifdef  _WIN64
#define VEHDATASIG VEHDATASIG_64
#else
#define VEHDATASIG VEHDATASIG_32
#endif

ALIGN struct VEH_SHELL_DATA
{
	ULONG_PTR	ImgBase;
	DWORD		ImgSize;
	DWORD		OSVersion;

	f_LdrpInvertedFunctionTable LdrpInvertedFunctionTable;
	f_LdrProtectMrdata			LdrProtectMrdata;
};

LONG __declspec(code_seg(".veh_sec$01")) CALLBACK VectoredHandlerShell(EXCEPTION_POINTERS * EP);
DWORD __declspec(code_seg(".veh_sec$02")) VEH_SEC_END();

__forceinline bool FindAndReplacePtr(BYTE * start, DWORD size, UINT_PTR stub, UINT_PTR value)
{
	if (!start)
	{
		return false;
	}

	auto end = start + size - sizeof(UINT_PTR);
	for (; start <= end; ++start)
	{
		if (*ReCa<UINT_PTR *>(start) == stub)
		{
			*ReCa<UINT_PTR *>(start) = value;

			return true;
		}
	}

	return false;
}