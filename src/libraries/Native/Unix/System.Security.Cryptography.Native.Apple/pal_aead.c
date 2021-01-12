// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "pal_aead.h"

int32_t AppleCryptoNative_AesGcm_Encrypt(void)
{
    return AppleCryptoNative_CryptoKit_AesGcm_Encrypt();
}
