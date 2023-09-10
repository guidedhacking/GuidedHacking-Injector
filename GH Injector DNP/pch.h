/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

#pragma once

#pragma warning(disable: 6258) //TerminateThread warning

#include <Windows.h>

#if (NTDDI_VERSION < NTDDI_WIN7)
#error The mininum requirement for this library is Windows 7.
#endif

#include <algorithm>
#include <cwctype>
#include <fstream>
#include <MetaHost.h>
#include <Psapi.h>
#include <sstream>
#include <vector>

inline HINSTANCE	g_hModuleBase = NULL;
inline HANDLE		g_hMainThread = NULL;

#define DEBUG_INFO

#ifdef DEBUG_INFO
#define CONSOLE_LOG printf
#else
#define CONSOLE_LOG
#endif