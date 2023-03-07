## GH Injector Library

A feature-rich DLL injection library which supports x86, WOW64 and x64 injections.
It features five injection methods, six  shellcode execution methods and various additional options.
Session separation can be bypassed with all methods.

If you want to use this library with a GUI check out the [GH Injector GUI](https://github.com/Broihon/GH-Injector-GUI).

----

### Injection methods

- LoadLibraryExW
- LdrLoadDll
- LdrpLoadDll
- LdrpLoadDllInternal
- ManualMapping

### Shellcode execution methods

- NtCreateThreadEx
- Thread hijacking
- SetWindowsHookEx
- QueueUserAPC
- KernelCallback
- FakeVEH

### Manual mapping features:

- Section mapping
- Base relocation
- Imports
- Delayed imports
- SEH support
- TLS initialization
- Security cookie initalization
- Loader Lock
- Shift image
- Clean datadirectories

### Additional features:

- Various cloaking options
	- PEB unlinking
	- PE header cloaking
	- Thread cloaking
- Handle hijacking
- Hook scanning/restoring

----

### Getting started

You can easily use mapper by including the compiled binaries in your project. Check the provided Injection.h header for more information.
Make sure you have the compiled binaries in the working directory of your program.
On first run the injection module has to download PDB files for the native (and when run on x64 the wow64) version of the ntdll.dll to resolve symbol addresses. Use the exported StartDownload function to begin the download.
The injector can only function if the downloads are finished. The injection module exports GetSymbolState and GetImportState which will return INJ_ERROR_SUCCESS (0) if the PDB download and resolving of all required addresses is completed.
Additionally GetDownloadProgress can be used to determine the progress of the download as percentage. If the injection module is to be unloaded during the download process call InterruptDownload or there's a chance that the dll will deadlock your process.

```cpp

#include "Injection.h"

HINSTANCE hInjectionMod = LoadLibrary(GH_INJ_MOD_NAME);
	
auto InjectA = (f_InjectA)GetProcAddress(hInjectionMod, "InjectA");
//auto Memory_Inject = (f_Memory_Inject)GetProcAddress(hInjectionMod, "Memory_Inject");
auto GetSymbolState = (f_GetSymbolState)GetProcAddress(hInjectionMod, "GetSymbolState");
auto GetImportState = (f_GetSymbolState)GetProcAddress(hInjectionMod, "GetImportState");
auto StartDownload = (f_StartDownload)GetProcAddress(hInjectionMod, "StartDownload");
auto GetDownloadProgressEx = (f_GetDownloadProgressEx)GetProcAddress(hInjectionMod, "GetDownloadProgressEx");

//due to a minor bug in the current version you have to wait a bit before starting the download
	//will be fixed in version 4.7
Sleep(500);

StartDownload();

//since GetSymbolState and GetImportState only return after the downloads are finished 
	//checking the download progress is not necessary
while (GetDownloadProgressEx(PDB_DOWNLOAD_INDEX_NTDLL, false) != 1.0f)
{
	Sleep(10);
}

#ifdef _WIN64
while (GetDownloadProgressEx(PDB_DOWNLOAD_INDEX_NTDLL, true) != 1.0f)
{
	Sleep(10);
}
#endif

while (GetSymbolState() != 0)
{
	Sleep(10);
}

while (GetImportState() != 0)
{
	Sleep(10);
}

DWORD TargetProcessId;

INJECTIONDATAA data =
{
	"",
	TargetProcessId,
	INJECTION_MODE::IM_LoadLibraryExW,
	LAUNCH_METHOD::LM_NtCreateThreadEx,
	MM_DEFAULT,
	0,
	NULL,
	NULL,
	true
};

strcpy(data.szDllPath, DllPathToInject);

InjectA(&data);

//Memory Inject
std::string dllFileName("dll-path");
std::ifstream instream(dllFileName.c_str(), std::ios::in | std::ios::binary);

if (instream)
{
	std::vector<uint8_t> dllBuff((std::istreambuf_iterator<char>(instream)), std::istreambuf_iterator<char>());

	MEMORY_INJECTIONDATA pData =
	{
		dllBuff.data(),
		dllBuff.size(),
		processInfo.dwProcessId,
		INJECTION_MODE::IM_ManualMap,
		LAUNCH_METHOD::LM_NtCreateThreadEx,
		MM_DEFAULT,
		0,
		NULL,
		NULL,
		true
	};

	Memory_Inject(&pData);
}

```

---

### Credits

First of all I want to credit Joachim Bauch whose Memory Module Library was a great source to learn from:  
https://github.com/fancycode/MemoryModule

He also made a great write-up explaining the basics of mapping a module:  
https://www.joachim-bauch.de/tutorials/loading-a-dll-from-memory/

I also want to thank Akaion/Dewera for helping me with SEH support and their C# mapping library which was another great resource to learn from:  
https://github.com/Dewera/Lunar

Big thanks to mambda who made this PDB parser which I could steal code from to verify GUIDs:  
https://bitbucket.org/mambda/pdb-parser/src/master/
