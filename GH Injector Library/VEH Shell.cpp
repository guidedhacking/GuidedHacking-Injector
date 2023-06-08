#pragma once
#include "pch.h"

#include "VEH Shell.h"

#pragma optimize( "", off ) //even with volatile this doesn't work, disabling optimizations seems to be the only way

// This code is 100% stolen from DarthTon:
// https://github.com/DarthTon/Blackbone/blob/master/src/BlackBone/ManualMap/MExcept.cpp
// Also Raymond Chen - of course - has written an article about C++ exception handling more than a decade ago:
// https://devblogs.microsoft.com/oldnewthing/20100730-00/?p=13273

#ifdef _WIN64

LONG __declspec(code_seg(".veh_sec$01")) CALLBACK VectoredHandlerShell(EXCEPTION_POINTERS * ExceptionInfo)
{
	volatile auto * pData = ReCa<VEH_SHELL_DATA *>(VEHDATASIG_64);

	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EH_EXCEPTION_NUMBER)
	{
		if (ExceptionInfo->ExceptionRecord->ExceptionInformation[2] >= pData->ImgBase && ExceptionInfo->ExceptionRecord->ExceptionInformation[2] < pData->ImgBase + pData->ImgSize)
		{
			if (ExceptionInfo->ExceptionRecord->ExceptionInformation[0] == EH_PURE_MAGIC_NUMBER1 && ExceptionInfo->ExceptionRecord->ExceptionInformation[3] == 0)
			{
				ExceptionInfo->ExceptionRecord->ExceptionInformation[0] = (ULONG_PTR)EH_MAGIC_NUMBER1;

				ExceptionInfo->ExceptionRecord->ExceptionInformation[3] = pData->ImgBase;
			}
		}
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

#else

__forceinline UINT_PTR bit_rotate_l(UINT_PTR val, int count)
{
	return (val << count) | (val >> (-count));
}

LONG __declspec(code_seg(".veh_sec$01")) CALLBACK VectoredHandlerShell(EXCEPTION_POINTERS * ExceptionInfo)
{
	UNREFERENCED_PARAMETER(ExceptionInfo);

	volatile auto * pData = ReCa<VEH_SHELL_DATA *>(VEHDATASIG_32);
	EXCEPTION_REGISTRATION_RECORD * pERR = nullptr;
	
	pERR = ReCa<EXCEPTION_REGISTRATION_RECORD *>(__readfsdword(0x00));

	if (!pERR)
	{
		return EXCEPTION_CONTINUE_SEARCH;
	}	

	RTL_INVERTED_FUNCTION_TABLE_ENTRY * Entries = nullptr;
	bool UseWin7Table = (pData->OSVersion == g_Win7);

	if (UseWin7Table)
	{
		Entries = &(ReCa<RTL_INVERTED_FUNCTION_TABLE_WIN7 *>(pData->LdrpInvertedFunctionTable))->Entries[0];
	}
	else
	{
		Entries = &pData->LdrpInvertedFunctionTable->Entries[0];
	}

	if (pData->OSVersion >= g_Win81)
	{
		pData->LdrProtectMrdata(FALSE);
	}

	auto cookie = *P_KUSER_SHARED_DATA_COOKIE;

	for (; pERR && pERR != ReCa<EXCEPTION_REGISTRATION_RECORD *>(0xFFFFFFFF) && pERR->Next != ReCa<EXCEPTION_REGISTRATION_RECORD *>(0xFFFFFFFF); pERR = pERR->Next)
	{
		for (ULONG idx = 0; idx < pData->LdrpInvertedFunctionTable->Count; ++idx)
		{
			if (!UseWin7Table && idx == 0)
			{
				continue;
			}

			if (Entries[idx].ImageBase != ReCa<void *>(pData->ImgBase))
			{
				continue;
			}

			if (ReCa<ULONG_PTR>(pERR->Handler) < pData->ImgBase || ReCa<ULONG_PTR>(pERR->Handler) >= pData->ImgBase + pData->ImgSize)
			{
				continue;
			}

			bool NewHandler = false;

			//DecodeSystemPointer
			DWORD ptr_enc = ReCa<DWORD>(Entries[idx].ExceptionDirectory);
			ptr_enc = bit_rotate_l(ptr_enc, cookie & 0x1F);
			ptr_enc ^= cookie;

			DWORD * pStart = ReCa<DWORD *>(ptr_enc);

			for (auto * pRVA = pStart; pRVA != nullptr && pRVA < pStart + 0x100; ++pRVA)
			{
				if (*pRVA == 0)
				{
					*pRVA = ReCa<DWORD>(pERR->Handler) - ReCa<DWORD>(Entries[idx].ImageBase);
										
					Entries[idx].ExceptionDirectorySize++;
					NewHandler = true;					

					break;
				}
				else if (ReCa<DWORD>(pERR->Handler) == ReCa<DWORD>(Entries[idx].ImageBase) + *pRVA)
				{
					break;
				}
			}

			if (NewHandler)
			{
				for (ULONG i = 0; i < Entries[idx].ExceptionDirectorySize; ++i)
				{
					for (ULONG j = Entries[idx].ExceptionDirectorySize - 1; j > i; --j)
					{
						if (pStart[j - 1] > pStart[j])
						{
							//high efficient xor-swap to outperform DarthTon's code 5Head
							pStart[j - 1] ^= pStart[j];
							pStart[j] ^= pStart[j - 1];
							pStart[j - 1] ^= pStart[j];
						}
					}
				}
			}
		}
	}

	if (pData->OSVersion >= g_Win81)
	{
		pData->LdrProtectMrdata(TRUE);
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

#endif

DWORD __declspec(code_seg(".veh_sec$02")) VEH_SEC_END()
{
	return 1339;
}

#pragma optimize( "", on)