// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "pal_evp_pkey_ed25519.h"
#include "pal_utilities.h"
#include "openssl.h"
#include <assert.h>

static int32_t ExportRawKeyMaterial(
    const EVP_PKEY* key,
    uint8_t* destination,
    int32_t destinationLength,
    int (*exporter)(const EVP_PKEY*, unsigned char*, size_t*))
{
    assert(key != NULL && destination != NULL && exporter != NULL);

    ERR_clear_error();

    size_t len = Int32ToSizeT(destinationLength);
    int result = exporter(key, destination, &len);

    if (result != 1)
    {
        return 0;
    }

    if (len != Int32ToSizeT(destinationLength))
    {
        assert("Exported raw key was not the correct length." && 0);
        return -1;
    }

    return 1;
}

int32_t CryptoNative_Ed25519Available(void)
{
    ERR_clear_error();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);

    if (ctx)
    {
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    // Ed25519 might not be available if OpenSSL was built without ECX support, or on OpenSSL 3
    // if the loaded provider configuration does not make Ed25519 available. In both cases,
    // ERR_R_UNSUPPORTED is put in the error queue.
    // If we errored for a different reason, we _still_ want to return "yes" for is supported.
    // This will allow for actual use of Ed25519 to throw the appropriate error.
    unsigned long error = ERR_peek_error();
    int32_t result = ERR_GET_REASON(error) == ERR_R_UNSUPPORTED ? 0 : 1;
    ERR_clear_error();
    return result;
}

int32_t CryptoNative_Ed25519ExportPrivateKey(const EVP_PKEY* key, uint8_t* destination, int32_t destinationLength)
{
    return ExportRawKeyMaterial(key, destination, destinationLength, EVP_PKEY_get_raw_private_key);
}

int32_t CryptoNative_Ed25519ExportPublicKey(const EVP_PKEY* key, uint8_t* destination, int32_t destinationLength)
{
    return ExportRawKeyMaterial(key, destination, destinationLength, EVP_PKEY_get_raw_public_key);
}

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

EVP_PKEY* CryptoNative_Ed25519ImportPrivateKey(const uint8_t* source, int32_t sourceLength)
{
    assert(source && sourceLength > 0);
    ERR_clear_error();

    return EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519,
        NULL,
        source,
        Int32ToSizeT(sourceLength));
}

EVP_PKEY* CryptoNative_Ed25519ImportPublicKey(const uint8_t* source, int32_t sourceLength)
{
    assert(source && sourceLength > 0);
    ERR_clear_error();

    return EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519,
        NULL,
        source,
        Int32ToSizeT(sourceLength));
}

int32_t CryptoNative_Ed25519SignData(
    EVP_PKEY* key, const uint8_t* data, int32_t dataLength, uint8_t* destination, int32_t destinationLength)
{
    assert(key != NULL && dataLength >= 0 && destination != NULL);
    ERR_clear_error();

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (ctx == NULL)
    {
        ERR_put_error(ERR_LIB_EVP, 0, ERR_R_MALLOC_FAILURE, __FILE__, __LINE__);
        return 0;
    }

    int32_t ret = 0;

    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) == 1)
    {
        size_t signatureLength = Int32ToSizeT(destinationLength);

        if (EVP_DigestSign(ctx, destination, &signatureLength, data, Int32ToSizeT(dataLength)) == 1)
        {
            if (signatureLength == Int32ToSizeT(destinationLength))
            {
                ret = 1;
            }
            else
            {
                assert("Signature was not the correct length." && 0);
                ret = -1;
            }
        }
    }

    EVP_MD_CTX_free(ctx);
    return ret;
}

int32_t CryptoNative_Ed25519VerifyData(
    EVP_PKEY* key, const uint8_t* data, int32_t dataLength, const uint8_t* signature, int32_t signatureLength)
{
    assert(key != NULL && dataLength >= 0 && signature != NULL && signatureLength > 0);
    ERR_clear_error();

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (ctx == NULL)
    {
        ERR_put_error(ERR_LIB_EVP, 0, ERR_R_MALLOC_FAILURE, __FILE__, __LINE__);
        return -1;
    }

    int32_t ret = -1;

    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1)
    {
        int verifyResult = EVP_DigestVerify(
            ctx,
            signature,
            Int32ToSizeT(signatureLength),
            data,
            Int32ToSizeT(dataLength));

        if (verifyResult == 1)
        {
            ret = 1;
        }
        else if (verifyResult == 0)
        {
            ret = 0;
        }
    }

    EVP_MD_CTX_free(ctx);
    return ret;
}
