## GH_Inj_Lib_DotNet

This is a complete implementation for .NET of the native library.

This implementation is created to work independently to the changes made to the library. I will explain in detail what it consists of.

----

### InjectionHelper 

It is the wrapper of the native library, it is made in C ++ and exposes the methods to be used in .NET.

Why don't you modify the origin library?

Keeping the Wrapper separately, allows the original author to continue working in his booksty without worrying about conflicts that may occur if I add or modify something to his original code. That is why Wapper remains separately in another DLL.

### GH_Inj_Lib_DotNet

This is the .net library that exposes all methods directly, to use the wrapper ('Injectionhelper')

### Inj_VB_Example

An example injector in VB, with everything implemented and ready for use.

### Additional features:

An example injector in C#, with everything implemented and ready for use.

----

### Getting started

1) Add the library to your C# or VB: **GH_Inj_Lib_DotNet**
2) Download and remove in the directory of your executable the last version of [GH Injection Library](https://github.com/Broihon/GH-Injector-Library/releases)
3) You are ready for use. Please check the sample example, to understand all its implementation.

### Preview


[!Preview](https://i.ibb.co/THnkTBY/test.png)



