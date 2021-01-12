// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#pragma once

#include "pal_types.h"

// Not callable from pinvoke; uses Swift calling convention
int32_t AppleCryptoNative_CryptoKit_AesGcm_Encrypt(void);
