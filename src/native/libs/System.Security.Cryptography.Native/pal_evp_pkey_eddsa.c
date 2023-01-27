// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "pal_utilities.h"
#include "pal_evp_pkey_eddsa.h"

#include <assert.h>

EVP_PKEY* CryptoNative_Ed25519GenerateKey(void)
{
    ERR_clear_error();

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);

    if (ctx == NULL)
    {
        return NULL;
    }

    EVP_PKEY* pkey = NULL;
    EVP_PKEY* ret = NULL;

    if (EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_keygen(ctx, &pkey) == 1)
    {
        ret = pkey;
        pkey = NULL;
    }

    if (pkey != NULL)
    {
        EVP_PKEY_free(pkey);
    }

    EVP_PKEY_CTX_free(ctx);
    return ret;
}

EVP_PKEY* CryptoNative_Ed25519ImportPrivateKey(const uint8_t* privateKey, int32_t privateKeyLength)
{
    assert(privateKey != NULL && privateKeyLength > 0);

    ERR_clear_error();
    size_t privateKeySize = Int32ToSizeT(privateKeyLength);
    return EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, privateKey, privateKeySize);
}

EVP_PKEY* CryptoNative_Ed25519ImportPublicKey(const uint8_t* publicKey, int32_t publicKeyLength)
{
    assert(publicKey != NULL && publicKeyLength > 0);

    ERR_clear_error();
    size_t publicKeySize = Int32ToSizeT(publicKeyLength);
    return EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, publicKey, publicKeySize);
}

int32_t CryptoNative_EdDsaExportPublicKey(
    const EVP_PKEY* pKey,
    uint8_t* publicKeyBuffer,
    int32_t publicKeyBufferLength,
    int32_t* publicKeyWritten)
{
    assert(pKey != NULL && publicKeyBuffer != NULL && publicKeyWritten != NULL && publicKeyBufferLength > 0);
    ERR_clear_error();

    *publicKeyWritten = 0;
    size_t bufferSize = Int32ToSizeT(publicKeyBufferLength);
    size_t neededSize = 0;

    if (!EVP_PKEY_get_raw_public_key(pKey, NULL, &neededSize))
    {
        return 0;
    }

    if (bufferSize < neededSize)
    {
        return -1;
    }

    int ret = EVP_PKEY_get_raw_public_key(pKey, publicKeyBuffer, &bufferSize);
    *publicKeyWritten = SizeTToInt32(bufferSize);
    return ret;
}

int32_t CryptoNative_EdDsaExportPrivateKey(
    const EVP_PKEY* pKey,
    uint8_t* privateKeyBuffer,
    int32_t privateKeyBufferLength,
    int32_t* privateKeyWritten)
{
    assert(pKey != NULL && privateKeyBuffer != NULL && privateKeyWritten != NULL && privateKeyBufferLength > 0);
    ERR_clear_error();

    *privateKeyWritten = 0;
    size_t bufferSize = Int32ToSizeT(privateKeyBufferLength);
    size_t neededSize = 0;

    if (!EVP_PKEY_get_raw_private_key(pKey, NULL, &neededSize))
    {
        return 0;
    }

    if (bufferSize < neededSize)
    {
        return -1;
    }

    int ret = EVP_PKEY_get_raw_private_key(pKey, privateKeyBuffer, &bufferSize);
    *privateKeyWritten = SizeTToInt32(bufferSize);
    return ret;
}

int32_t CryptoNative_EdDsaVerifyData(
    EVP_PKEY* pKey,
    const uint8_t* data,
    int32_t dataLength,
    const uint8_t* signature,
    int32_t signatureLength,
    int32_t* validSignature)
{
    assert(pKey != NULL && signature != NULL && signatureLength > 0 && validSignature != NULL);
    *validSignature = 0;

    ERR_clear_error();
    EVP_MD_CTX* digestCtx = EVP_MD_CTX_new();

    if (digestCtx == NULL)
    {
        return 0;
    }

    size_t dataSize = Int32ToSizeT(dataLength);
    size_t signatureSize = Int32ToSizeT(signatureLength);
    int32_t ret = 0;

    if ((ret = EVP_DigestVerifyInit(digestCtx, NULL, NULL, NULL, pKey)) != 1)
    {
        goto cleanup;
    }

    int verify = EVP_DigestVerify(digestCtx, signature, signatureSize, data, dataSize);

    if (verify == 1)
    {
        *validSignature = 1;
    }
    else if (verify == 0)
    {
        // Zero for EVP_DigestVerify means the operation succeeded, but the signature is invalid.
        // Return 1 to indicate the call succeeded and leave validSignature as 0.
        ret = 1;
    }
    else
    {
        ret = verify;
    }

cleanup:
    EVP_MD_CTX_free(digestCtx);
    return ret;
}

int32_t CryptoNative_EdDsaSignData(
    EVP_PKEY* pKey,
    const uint8_t* data,
    int32_t dataLength,
    uint8_t* signatureBuffer,
    int32_t signatureBufferLength,
    int32_t* signatureWritten)
{
    assert(pKey != NULL && signatureBuffer != NULL && signatureBufferLength > 0 && dataLength >= 0 && signatureWritten != NULL);
    *signatureWritten = 0;

    ERR_clear_error();

    EVP_MD_CTX* digestCtx = EVP_MD_CTX_new();

    if (digestCtx == NULL)
    {
        return 0;
    }

    size_t signatureLength = 0;
    size_t dataSize = Int32ToSizeT(dataLength);
    const size_t signatureBufferSize = Int32ToSizeT(signatureBufferLength);
    int32_t ret = 0;

    if ((ret = EVP_DigestSignInit(digestCtx, NULL, NULL, NULL, pKey)) != 1)
    {
        goto cleanup;
    }

    if ((ret = EVP_DigestSign(digestCtx, NULL, &signatureLength, data, dataSize)) != 1)
    {
        goto cleanup;
    }

    if (signatureBufferSize < signatureLength)
    {
        ret = -1;
        goto cleanup;
    }

    signatureLength = signatureBufferSize;

    if ((ret = EVP_DigestSign(digestCtx, signatureBuffer, &signatureLength, data, dataSize)) != 1)
    {
        goto cleanup;
    }

    *signatureWritten = SizeTToInt32(signatureLength);

cleanup:
    EVP_MD_CTX_free(digestCtx);
    return ret;
}
