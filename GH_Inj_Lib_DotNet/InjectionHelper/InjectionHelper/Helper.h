#include "stdafx.h"
#include "Injection.h"

//using f_InjectA = DWORD(__stdcall*)(INJECTIONDATAA * pData);
//using f_InjectW = DWORD(__stdcall*)(INJECTIONDATAW * pData);

typedef DWORD(*f_InjectA)(INJECTIONDATAA * pData);
typedef DWORD(*f_InjectW)(INJECTIONDATAW * pData);


//using f_ValidateInjectionFunctions = bool(__stdcall*)(DWORD dwTargetProcessId, DWORD & ErrorCode, DWORD & LastWin32Error, HookInfo * HookDataOut, UINT Count, UINT * CountOut);
//using f_RestoreInjectionFunctions = bool(__stdcall*)(DWORD dwTargetProcessId, DWORD & ErrorCode, DWORD & LastWin32Error, HookInfo * HookDataIn, UINT Count, UINT * CountOut);

typedef bool(*f_ValidateInjectionFunctions)(DWORD dwTargetProcessId, DWORD & ErrorCode, DWORD & LastWin32Error, HookInfo * HookDataOut, UINT Count, UINT * CountOut);
typedef bool(*f_RestoreInjectionFunctions)(DWORD dwTargetProcessId, DWORD & ErrorCode, DWORD & LastWin32Error, HookInfo * HookDataIn, UINT Count, UINT * CountOut);

//using f_GetVersionA = HRESULT(__stdcall *)(char		* out, size_t cb_size);
//using f_GetVersionW = HRESULT(__stdcall *)(wchar_t	* out, size_t cb_size);

typedef HRESULT(*f_GetVersionA)(char	* out, size_t cb_size);
typedef HRESULT(*f_GetVersionW)(wchar_t	* out, size_t cb_size);


//using f_GetSymbolState = DWORD(__stdcall *)();
//using f_GetImportState = DWORD(__stdcall *)();

typedef float(*f_GetDownloadProgress);
typedef DWORD(*f_GetSymbolState)();
typedef DWORD(*f_GetImportState)();

//using f_GetDownloadProgressEx = float(__stdcall *)(int index, bool bWow64);
//using f_StartDownload = void(__stdcall *)();
//using f_InterruptDownload = void(__stdcall *)();


//using f_GetDownloadProgressEx = float(__stdcall *)(int index, bool bWow64);

typedef float(*f_GetDownloadProgressEx)(int index, bool bWow64);
typedef void(*f_StartDownload)();
typedef void(*f_InterruptDownload)();

//using f_raw_print_callback = void(__stdcall *)(const char * szText);
//using f_SetRawPrintCallback = DWORD(__stdcall *)(f_raw_print_callback callback);

typedef void(*f_raw_print_callback)(const char * szText);
typedef DWORD(*f_SetRawPrintCallback)(f_raw_print_callback callback);