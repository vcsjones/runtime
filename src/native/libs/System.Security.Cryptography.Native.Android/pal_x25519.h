// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#pragma once

#include "pal_compiler.h"
#include "pal_jni.h"
#include "pal_types.h"

PALEXPORT int32_t AndroidCryptoNative_X25519IsSupported(void);

PALEXPORT void AndroidCryptoNative_X25519DestroyKey(jobject key);

PALEXPORT int32_t AndroidCryptoNative_X25519GenerateKey(jobject* publicKey, jobject* privateKey);
