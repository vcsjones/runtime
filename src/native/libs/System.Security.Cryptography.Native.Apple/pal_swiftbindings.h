// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#pragma once

#include "pal_types.h"
#include "pal_compiler.h"

PALEXPORT int32_t AppleCryptoNative_Ed25519Generate(
    uint8_t* privateKeyBuffer,
    int32_t privateKeyBufferLength,
    uint8_t* publicKeyBuffer,
    int32_t publicKeyBufferLength,
    int32_t* privateKeyWritten,
    int32_t* publicKeyWritten);

PALEXPORT int32_t AppleCryptoNative_Ed25519Sign(
    uint8_t* privateKeyPtr,
    int32_t privateKeyLength,
    uint8_t* dataPtr,
    int32_t dataLength,
    uint8_t* signatureBuffer,
    int32_t signatureBufferLength,
    int32_t* signatureWritten);

PALEXPORT int32_t AppleCryptoNative_Ed25519Verify(
    uint8_t* publicKeyPtr,
    int32_t publicKeyLength,
    uint8_t* dataPtr,
    int32_t dataLength,
    uint8_t* signaturePtr,
    int32_t signatureLength,
    int32_t* validSignature);

PALEXPORT int32_t AppleCryptoNative_Ed25519ValidPrivateKey(
    uint8_t* privateKeyPtr,
    int32_t privateKeyLength,
    uint8_t* publicKeyBuffer,
    int32_t publicKeyBufferLength,
    int32_t* publicKeyWritten,
    int32_t* validPrivateKey);

PALEXPORT int32_t AppleCryptoNative_Ed25519ValidPublicKey(
    uint8_t* publicKeyPtr,
    int32_t publicKeyLength);

PALEXPORT int32_t AppleCryptoNative_ChaCha20Poly1305Encrypt(
    uint8_t* keyPtr,
    int32_t keyLength,
    uint8_t* noncePtr,
    int32_t nonceLength,
    uint8_t* plaintextPtr,
    int32_t plaintextLength,
    uint8_t* ciphertextBuffer,
    int32_t ciphertextBufferLength,
    uint8_t* tagBuffer,
    int32_t tagBufferLength,
    uint8_t* aadPtr,
    int32_t aadLength);

PALEXPORT int32_t AppleCryptoNative_ChaCha20Poly1305Decrypt(
    uint8_t* keyPtr,
    int32_t keyLength,
    uint8_t* noncePtr,
    int32_t nonceLength,
    uint8_t* ciphertextPtr,
    int32_t ciphertextLength,
    uint8_t* tagPtr,
    int32_t tagLength,
    uint8_t* plaintextBuffer,
    int32_t plaintextBufferLength,
    uint8_t* aadPtr,
    int32_t aadLength);

PALEXPORT int32_t AppleCryptoNative_AesGcmEncrypt(
    uint8_t* keyPtr,
    int32_t keyLength,
    uint8_t* noncePtr,
    int32_t nonceLength,
    uint8_t* plaintextPtr,
    int32_t plaintextLength,
    uint8_t* ciphertextBuffer,
    int32_t ciphertextBufferLength,
    uint8_t* tagBuffer,
    int32_t tagBufferLength,
    uint8_t* aadPtr,
    int32_t aadLength);

PALEXPORT int32_t AppleCryptoNative_AesGcmDecrypt(
    uint8_t* keyPtr,
    int32_t keyLength,
    uint8_t* noncePtr,
    int32_t nonceLength,
    uint8_t* ciphertextPtr,
    int32_t ciphertextLength,
    uint8_t* tagPtr,
    int32_t tagLength,
    uint8_t* plaintextBuffer,
    int32_t plaintextBufferLength,
    uint8_t* aadPtr,
    int32_t aadLength);
