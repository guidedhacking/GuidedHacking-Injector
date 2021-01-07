## GH Injector Library

A feature-rich DLL injection library which supports x86, WOW64 and x64 injections.
It features five injection methods, four shellcode execution methods and various additional options.
Session seperation can be bypassed with all methods.

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

### Manual mapping features:

- Section mapping
- Base relocation
- Imports
- Delayed imports
- SEH support
- TLS initialization
- Security cookie initalization

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
On first run the injection module will download pdb files for the native (and when run on x64 the wow64) version of the ntdll.dll to resolve symbol addresses.
The injector can only function if that process is finished. The injection module exports GetSymbolState which will return INJ_ERROR_SUCCESS (0) if the pdb download and resolving of all required addresses is completed.
Additionally GetDownloadProgress can be used to determine the progress of the download as percentage.

```cpp

#include "Injection.h"

HINSTANCE hInjectionMod = LoadLibrary(GH_INJ_MOD_NAME);
	
auto InjectA = (f_InjectA)GetProcAddress(hInjectionMod, "InjectA");
auto GetSymbolState = (f_GetSymbolState)GetProcAddress(hInjectionMod, "GetSymbolState");

while (GetSymbolState() != 0)
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
	NULL,
	0,
	NULL,
	true
};

strcpy(data.szDllPath, DllPathToInject);

InjectA(&data);

```

---

### Credits

First of all I want to credit Joachim Bauch whose Memory Module Library was a great source to learn from:  
https://github.com/fancycode/MemoryModule

He also made a great write-up explaining the basics of mapping a moule:  
https://www.joachim-bauch.de/tutorials/loading-a-dll-from-memory/

I also want to thank Akaion for helping me with SEH support and their C# mapping library which was a great resource to learn from:  
https://github.com/Dewera/Lunar

Big thanks to mambda who made this PDB parser which I could steal code from to verify GUIDs:  
https://bitbucket.org/mambda/pdb-parser/src/master/
