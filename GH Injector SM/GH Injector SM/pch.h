/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

#pragma once

#include <Windows.h>

#if (NTDDI_VERSION < NTDDI_WIN7)
#error The mininum requirement for this library is Windows 7.
#endif

#include <fstream>
#include <sstream>
#include <vector>