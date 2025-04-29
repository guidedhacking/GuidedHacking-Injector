# GuidedHacking DLL Injector Library

A feature-rich DLL injection library which supports x86, WOW64 and x64 injections.
Developed by [Broihon](https://guidedhacking.com/members/broihon.49430/) for Guided Hacking.
It features five injection methods, six  shellcode execution methods and various additional options.
Session separation can be bypassed with all methods.

If you want to use this library with a GUI check out the [GH Injector GUI](https://github.com/guided-hacking/GH-Injector-GUI).

Release Downloads: [Download DLL Injector Here ](https://guidedhacking.com/resources/guided-hacking-dll-injector.4/)

![image](https://github.com/guided-hacking/GH-Injector-Library/assets/15186628/d5c6670c-538f-4a48-a565-bb277e4dc46e)
![image](https://github.com/guided-hacking/GH-Injector-Library/assets/15186628/3ca83e0f-0e8b-4bc9-a101-0bb28e105698)![image](https://github.com/guided-hacking/GH-Injector-Library/assets/15186628/d070f0f0-8469-48f1-9744-6b199f0d1b73)

----

### DLL Injection methods

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

### DLL Manual mapping features:

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

<h3>Official Guided Hacking Courses</h3>
<ul>
	<li><a href="https://guidedhacking.com/ghb" target="_blank">The Game Hacking Bible</a>&nbsp;- a massive 70 chapter Game Hacking Course</li>
	<li><a href="https://guidedhacking.com/threads/squally-cs420-game-hacking-course.14191/" target="_blank">Computer Science 420</a>&nbsp;- an eight chapter lecture on CS, Data Types &amp; Assembly</li>
	<li><a href="https://guidedhacking.com/forums/binary-exploit-development-course.551/" target="_blank">Binary Exploit Development</a>&nbsp;- a 9 chapter series on exploit dev&nbsp;from a certified OSED</li>
	<li><a href="https://guidedhacking.com/forums/game-hacking-shenanigans/" target="_blank">Game Hacking Shenanigans</a>&nbsp;- a twenty lesson Cheat Engine hacking course</li>
	<li><a href="https://guidedhacking.com/threads/python-game-hacking-tutorial-1-1-introduction.18695/" target="_blank">Python Game Hacking Course</a>&nbsp;- 7 chapter external &amp; internal python hack lesson</li>
	<li><a href="https://guidedhacking.com/threads/python-game-hacking-tutorial-2-1-introduction.19199/" target="_blank">Python App Reverse Engineering</a>&nbsp;- Learn to reverse python apps in 5 lessons</li>
	<li><a href="https://guidedhacking.com/threads/web-browser-game-hacking-intro-part-1.17726/" target="_blank">Web Browser Game Hacking</a>&nbsp;- Hack javascript games with this 4 chapter course</li>
	<li><a href="https://guidedhacking.com/forums/roblox-exploit-scripting-course-res100.521/" target="_blank">Roblox Exploiting Course</a>&nbsp;- 7 Premium Lessons on Hacking Roblox</li>
	<li><a href="https://guidedhacking.com/forums/java-reverse-engineering-course-jre100.538/" target="_blank">Java Reverse Engineering Course</a>&nbsp;- 5 chapter beginner guide</li>
	<li><a href="https://guidedhacking.com/forums/java-game-hacking-course-jgh100.553/" target="_blank">Java Game Hacking Course</a>&nbsp;- 6 Chapter Beginner Guide</li>
</ul>

----

### Where to download the compiled binaries?
This repo doesn't contain the compiled binaries, just the source code for the library. If you want to download the compiled program, you must be a paying customer on our website where you can download it. If you can compile it yourself and get it working, then great, enjoy it, but you do not have permission/license to distribute the compiled binaries or any of our other content from our website.

### Getting Started With The GH DLL Injector

You can easily use mapper by including the compiled binaries in your project. Check the provided Injection.h header for more information.
Make sure you have the compiled binaries in the working directory of your program.
On first run the injection module has to download PDB files for the native (and when run on x64 the wow64) version of the ntdll.dll to resolve symbol addresses. Use the exported StartDownload function to begin the download.
The injector can only function if the downloads are finished. The injection module exports GetSymbolState and GetImportState which will return INJ_ERROR_SUCCESS (0) if the PDB download and resolving of all required addresses is completed.
Additionally GetDownloadProgress can be used to determine the progress of the download as percentage. If the injection module is to be unloaded during the download process call InterruptDownload or there's a chance that the dll will deadlock your process.

```cpp

#include "Injection.h"

HINSTANCE hInjectionMod = LoadLibrary(GH_INJ_MOD_NAME);
	
auto InjectA = (f_InjectA)GetProcAddress(hInjectionMod, "InjectA");
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
	NULL,
	0,
	NULL,
	NULL,
	true
};

strcpy(data.szDllPath, DllPathToInject);

InjectA(&data);

```

---

### What is a DLL Injector?​

DLL injection is a technique where code is run in the space of another process by forcing it to load a dynamic library. This is often done by external programs to change the behavior of the target program in an unintended way. For example, injected code could hook function calls or copy data variables. A program used to inject code into processes is called a DLL injector

If you're making an internal hack you must use a DLL injector to inject it.

### What is a DLL?​

A DLL is a library of code that is loaded into a process at runtime. Large code bases led to the development of libraries like SSL and cURL, which are used by many programs. These libraries are statically linked, meaning that every executable includes the code from the library. However, this can lead to a lot of wasted disk space if multiple programs all statically link the same library.

Dynamic link libraries were created in order to save space on smaller hard drives. With DLLs, there only needs to be one copy on the hard drive, and hundreds of programs can dynamically load and resolve them at run time.

### Why is DLL injection so common?​

It's common because the easiest way to modify a program is via hooking, especially when you want to display something on the screen or make a copy of what's on the screen. You can hook things without a DLL but importing 1 file which does everything is a modular and convenient way of performing this task. In addition, when you inject a DLL, it's code is running inside the target process, which is much faster than doing the same task from an external program.

DLL injection is so popular for game hacking for the same reasons. Rather than modifying a program externally, you can get your code executing inside the process, which allows for easy & efficient hooking and memory modification.

### DLL Injector Credits

Special thank you to [Kage](https://guidedhacking.com/members/kage.109622/) / [Multikill](https://github.com/multikill) for developing the Qt GUI of the GH Injector, it's a a huge improvement.

First of all I want to credit Joachim Bauch whose Memory Module Library was a great source to learn from:  
https://github.com/fancycode/MemoryModule

He also made a great write-up explaining the basics of mapping a module:  
https://www.joachim-bauch.de/tutorials/loading-a-dll-from-memory/

I also want to thank Akaion/Dewera for helping me with SEH support and their C# mapping library which was another great resource to learn from:  
[C# Manual Map DLL Injection Library](https://guidedhacking.com/threads/c-manual-map-dll-injection-library-lunar.14238/)

Big thanks to mambda who made this PDB parser which I could steal code from to verify GUIDs:  
[C++ Windows PDB Parser](https://guidedhacking.com/threads/windows-c-pdb-parser.12159/)

GuidedHacking® - The Game Hacking Bible® - © 2025 Guided Hacking LLC. All Rights Reserved.
