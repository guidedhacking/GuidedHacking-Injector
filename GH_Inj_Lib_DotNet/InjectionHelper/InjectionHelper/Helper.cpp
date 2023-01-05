#include "stdafx.h"
#include "Injection.h"
#include "Helper.h"
#include <process.h>
#include <stdio.h>
#include <list>

//#include <cstdio>

//#include <iostream>
//#include <string>

//using namespace std;


typedef void (*callback_function)();

typedef void (*callback_DLLInjected)(char * , DWORD);

struct INJECTIONDATAEx
{
	callback_DLLInjected aDLLCallback;
	DWORD TargetProcessId;
	char* DllPathToInject;
	DWORD INJECTION_MODE_Ex;
	DWORD LAUNCH_METHOD_Ex;
	DWORD FlagsEx;
    DWORD TimeoutEx;
	bool GenerateErrorLog;
};

HINSTANCE hInjectionMod = NULL;

wchar_t *convertCharArrayToLPCWSTR(const char* charArray)
{
    wchar_t* wString=new wchar_t[4096];
    MultiByteToWideChar(CP_ACP, 0, charArray, -1, wString, 4096);
    return wString;
}


char* wchar_to_char(const wchar_t* pwchar)
{
    // get the number of characters in the string.
    int currentCharIndex = 0;
    char currentChar = pwchar[currentCharIndex];

    while (currentChar != '\0')
    {
        currentCharIndex++;
        currentChar = pwchar[currentCharIndex];
    }

    const int charCount = currentCharIndex + 1;

    // allocate a new block of memory size char (1 byte) instead of wide char (2 bytes)
    char* filePathC = (char*)malloc(sizeof(char) * charCount);

    for (int i = 0; i < charCount; i++)
    {
        // convert to char (1 byte)
        char character = pwchar[i];

        *filePathC = character;

        filePathC += sizeof(char);

    }
    filePathC += '\0';

    filePathC -= (sizeof(char) * charCount);

    return filePathC;
}

extern "C" __declspec(dllexport) char* GetModName()
{
 char* ModDLLName = wchar_to_char(GH_INJ_MOD_NAME);
free;
 return ModDLLName;
}



extern "C" __declspec(dllexport) float GetDownloadProgress(bool Isx64)
{

 auto GetDownloadProgressEx = (f_GetDownloadProgressEx)GetProcAddress(hInjectionMod, "GetDownloadProgressEx");

 float ProgressEx = GetDownloadProgressEx(PDB_DOWNLOAD_INDEX_NTDLL, Isx64);

 //free;
 return ProgressEx;
}

extern "C" __declspec(dllexport) bool Ini()
{
  hInjectionMod = LoadLibrary(GH_INJ_MOD_NAME);
  if (hInjectionMod == 0)
	  {
    return false;
      } else {
    return true;
      }
}

extern "C" __declspec(dllexport) void SetManualHook(char* HookName)
{
	HMODULE HandleEX = GetModuleHandleA(HookName);
    hInjectionMod = HandleEX;
}

callback_function aCallbackEx;

DWORD WINAPI SymbolsFuncs(LPVOID lpParameter)
{
	try {
	auto GetSymbolState = (f_GetSymbolState)GetProcAddress(hInjectionMod, "GetSymbolState");
    auto GetImportState = (f_GetSymbolState)GetProcAddress(hInjectionMod, "GetImportState");
	auto StartDownload = (f_StartDownload)GetProcAddress(hInjectionMod, "StartDownload");

StartDownload();

while (GetSymbolState() != 0)
{
	Sleep(10);
}

while (GetImportState() != 0)
{
	Sleep(10);
}

aCallbackEx();
	   }
catch (char *excp) {
  
} 
    return 0;
}


extern "C" __declspec(dllexport) void DownloadAndImportSymbols(callback_function aCallback)
{
	aCallbackEx = aCallback;
	 // Create a new thread which will start at the DoStuff function
    HANDLE hThread = CreateThread(
        NULL,    // Thread attributes
        0,       // Stack size (0 = use default)
        SymbolsFuncs,
        NULL,    // Parameter to pass to the thread
        0,       // Creation flags
        NULL);   // Thread id
  
	if (hThread != NULL)
    {
   
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    }
	
}

INJECTIONDATAEx InjectInfoEx;

DWORD WINAPI InjectEx(LPVOID lpParameter)
{
    
try {
 
auto InjectA = (f_InjectA)GetProcAddress(hInjectionMod, "InjectA");
   
INJECTION_MODE InjMode =  GetInjMode(InjectInfoEx.INJECTION_MODE_Ex);

LAUNCH_METHOD LachMode =  GetLchMehod(InjectInfoEx.LAUNCH_METHOD_Ex);

INJECTIONDATAA data =
{
	"",
	InjectInfoEx.TargetProcessId,
	InjMode,
	LachMode,
	InjectInfoEx.FlagsEx,
	InjectInfoEx.TimeoutEx,
	NULL,
	NULL,
	InjectInfoEx.GenerateErrorLog //WritteLog
};

strcpy(data.szDllPath, InjectInfoEx.DllPathToInject);

DWORD InjectResult = InjectA(&data);

InjectInfoEx.aDLLCallback(InjectInfoEx.DllPathToInject,InjectResult);

}
catch (char *excp) {
  InjectInfoEx.aDLLCallback(excp,40000100);
} 
    return 0;
}

extern "C" __declspec(dllexport) void Inject(callback_DLLInjected aDLLCallback,DWORD TargetProcessId, char* DllPathToInject, DWORD INJECTION_MODE_Ex, DWORD LAUNCH_METHOD_Ex, DWORD FlagsEx,DWORD TimeoutEx, bool WritteLog)
{
	
	InjectInfoEx.aDLLCallback = aDLLCallback;
	InjectInfoEx.TargetProcessId = TargetProcessId;
	InjectInfoEx.DllPathToInject = DllPathToInject;
	InjectInfoEx.INJECTION_MODE_Ex = INJECTION_MODE_Ex;
	InjectInfoEx.LAUNCH_METHOD_Ex = LAUNCH_METHOD_Ex;
	InjectInfoEx.FlagsEx = FlagsEx;
	InjectInfoEx.TimeoutEx = TimeoutEx;
	InjectInfoEx.GenerateErrorLog = WritteLog;

	 // Create a new thread which will start at the DoStuff function
    HANDLE hThread = CreateThread(
        NULL,    // Thread attributes
        0,       // Stack size (0 = use default)
        InjectEx,
        NULL,    // Parameter to pass to the thread
        0,       // Creation flags
        NULL);   // Thread id
  
	if (hThread != NULL)
    {
   
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    }

   
}
