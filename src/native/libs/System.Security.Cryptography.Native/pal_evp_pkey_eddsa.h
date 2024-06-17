// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "pal_types.h"
#include "pal_compiler.h"
#include "opensslshim.h"

PALEXPORT EVP_PKEY* CryptoNative_Ed25519GenerateKey(void);

PALEXPORT int32_t CryptoNative_EdDsaExportPublicKey(
    const EVP_PKEY* pKey,
    uint8_t* publicKeyBuffer,
    int32_t publicKeyBufferLength,
    int32_t* publicKeyWritten);

PALEXPORT int32_t CryptoNative_EdDsaExportPrivateKey(
    const EVP_PKEY* pKey,
    uint8_t* privateKeyBuffer,
    int32_t privateKeyBufferLength,
    int32_t* privateKeyWritten);

PALEXPORT EVP_PKEY* CryptoNative_Ed25519ImportPublicKey(const uint8_t* publicKey, int32_t publicKeyLength);
PALEXPORT EVP_PKEY* CryptoNative_Ed25519ImportPrivateKey(const uint8_t* privateKey, int32_t privateKeyLength);

PALEXPORT int32_t CryptoNative_EdDsaSignData(
    EVP_PKEY* pKey,
    const uint8_t* data,
    int32_t dataLength,
    uint8_t* signatureBuffer,
    int32_t signatureBufferLength,
    int32_t* signatureWritten);

PALEXPORT int32_t CryptoNative_EdDsaVerifyData(
    EVP_PKEY* pKey,
    const uint8_t* data,
    int32_t dataLength,
    const uint8_t* signature,
    int32_t signatureLength,
    int32_t* validSignature);

PALEXPORT int32_t CryptoNative_EdDsaHasPrivateKey(EVP_PKEY* pKey);
