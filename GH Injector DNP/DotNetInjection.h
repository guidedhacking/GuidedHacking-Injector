﻿/*
 * Author:       Broihon
 * Copyright:    Guided Hacking™ © 2012-2023 Guided Hacking LLC
*/

#pragma once

#include "pch.h"

#define FILENAME L"\\DNPD.txt"

DWORD __stdcall LoadDotNetBinary(void * pArg);

#define DNP_ERR_SUCCESS				0x00000000

#define DNP_ERR_CANT_OPEN_FILE		0x60000001
#define DNP_ERR_EMPTY_FILE			0x60000002
#define DNP_ERR_OUT_OF_MEMORY		0x60000003
#define DNP_ERR_INVALID_DATA		0x60000004
#define DNP_ERR_HRESULT				0x60000005
#define DNP_ERR_CANT_FIND_MODULE	0x60000006