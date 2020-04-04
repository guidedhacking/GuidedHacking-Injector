## GH Injector Library

A feature-rich DLL injection library which supports x86, WOW64 and x64 injections.
It features four injection methods, four shellcode execution methods and various additional options.
Session seperation can be bypassed with all methods.

----

### Injection methods

- LoadLibraryExW
- LdrLoadDll
- LdrpLoadDll
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

### Additional features
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

```cpp

#include "Injection.h"

HINSTANCE hInjectionMod = LoadLibrary(GH_INJ_MOD_NAME);
	
auto InjectA = (f_InjectA)GetProcAddress(hInjectionMod, "InjectA");

DWORD TargetProcessId;

INJECTIONDATAA data =
{
	0,
	"",
	TargetProcessId;,
	INJECTION_MODE::IM_LoadLibraryExW,
	LAUNCH_METHOD::LM_NtCreateThreadEx,
	NULL,
	0,
	NULL
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
