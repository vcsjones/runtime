// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "opensslshim.h"
#include "pal_compiler.h"
#include "pal_types.h"

PALEXPORT int32_t CryptoNative_X25519ExportPrivateKey(const EVP_PKEY* key, uint8_t* destination, int32_t destinationLength);
PALEXPORT int32_t CryptoNative_X25519ExportPublicKey(const EVP_PKEY* key, uint8_t* destination, int32_t destinationLength);

PALEXPORT EVP_PKEY* CryptoNative_X25519ImportPrivateKey(const uint8_t* source, int32_t sourceLength);
PALEXPORT EVP_PKEY* CryptoNative_X25519ImportPublicKey(const uint8_t* source, int32_t sourceLength);

/*
Generates a new EVP_PKEY.
*/
PALEXPORT EVP_PKEY* CryptoNative_X25519GenerateKey(void);

