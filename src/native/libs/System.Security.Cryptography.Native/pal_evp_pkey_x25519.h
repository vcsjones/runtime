// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "opensslshim.h"
#include "pal_compiler.h"
#include "pal_types.h"

/*
Generates a new EVP_PKEY.
*/
PALEXPORT EVP_PKEY* CryptoNative_X25519GenerateKey(void);
