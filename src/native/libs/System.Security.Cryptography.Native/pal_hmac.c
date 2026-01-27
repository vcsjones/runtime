// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "pal_config.h"
#include "pal_utilities.h"
#include "pal_hmac.h"

#include <assert.h>

#define HMAC_MAX_BLOCK_SIZE (136)

HMAC_CTX* CryptoNative_HmacCreate(const uint8_t* key, int32_t keyLen, const EVP_MD* md)
{
    assert(key != NULL || keyLen == 0);
    assert(keyLen >= 0);
    assert(md != NULL);

    ERR_clear_error();

    HMAC_CTX* ctx = HMAC_CTX_new();

    if (ctx == NULL)
    {
        // Allocation failed
        // This is one of the few places that don't report the error to the queue, so
        // we'll do it here.
        ERR_put_error(ERR_LIB_EVP, 0, ERR_R_MALLOC_FAILURE, __FILE__, __LINE__);
        return NULL;
    }

    // NOTE: We can't pass NULL as empty key since HMAC_Init_ex will interpret
    // that as request to reuse the "existing" key.
    uint8_t _;
    if (keyLen == 0)
        key = &_;

    int ret = HMAC_Init_ex(ctx, key, keyLen, md, NULL);

    if (!ret)
    {
        HMAC_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

void CryptoNative_HmacDestroy(HMAC_CTX* ctx)
{
    if (ctx != NULL)
    {
        HMAC_CTX_free(ctx);
    }
}

int32_t CryptoNative_HmacReset(HMAC_CTX* ctx)
{
    assert(ctx != NULL);

    ERR_clear_error();

    return HMAC_Init_ex(ctx, NULL, 0, NULL, NULL);
}

int32_t CryptoNative_HmacUpdate(HMAC_CTX* ctx, const uint8_t* data, int32_t len)
{
    assert(ctx != NULL);
    assert(data != NULL || len == 0);
    assert(len >= 0);

    ERR_clear_error();

    if (len < 0)
    {
        return 0;
    }

    return HMAC_Update(ctx, data, Int32ToSizeT(len));
}

int32_t CryptoNative_HmacFinal(HMAC_CTX* ctx, uint8_t* md, int32_t* len)
{
    assert(ctx != NULL);
    assert(len != NULL);
    assert(md != NULL || *len == 0);
    assert(*len >= 0);

    ERR_clear_error();

    if (len == NULL || *len < 0)
    {
        return 0;
    }

    unsigned int unsignedLen = Int32ToUint32(*len);
    int ret = HMAC_Final(ctx, md, &unsignedLen);
    *len = Uint32ToInt32(unsignedLen);
    return ret;
}

HMAC_CTX* CryptoNative_HmacCopy(const HMAC_CTX* ctx)
{
    assert(ctx != NULL);

    ERR_clear_error();

    HMAC_CTX* dup = HMAC_CTX_new();

    if (dup == NULL)
    {
        // This is one of the few places that don't report the error to the queue, so
        // we'll do it here.
        ERR_put_error(ERR_LIB_EVP, 0, ERR_R_MALLOC_FAILURE, __FILE__, __LINE__);
        return NULL;
    }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual"
    if (!HMAC_CTX_copy(dup, (HMAC_CTX*)ctx))
#pragma clang diagnostic pop
    {
        HMAC_CTX_free(dup);
        return NULL;
    }

    return dup;
}

int32_t CryptoNative_HmacCurrent(const HMAC_CTX* ctx, uint8_t* md, int32_t* len)
{
    assert(ctx != NULL);
    assert(len != NULL);
    assert(md != NULL || *len == 0);
    assert(*len >= 0);

    ERR_clear_error();

    if (len == NULL || *len < 0)
    {
        return 0;
    }

    HMAC_CTX* dup = CryptoNative_HmacCopy(ctx);

    if (dup != NULL)
    {
        int ret = CryptoNative_HmacFinal(dup, md, len);
        HMAC_CTX_free(dup);
        return ret;
    }

    return 0;
}

int32_t CryptoNative_HmacOneShot(const EVP_MD* type,
                                 const uint8_t* key,
                                 int32_t keySize,
                                 const uint8_t* source,
                                 int32_t sourceSize,
                                 uint8_t* md,
                                 int32_t* mdSize)
{
    assert(mdSize != NULL && type != NULL && md != NULL && mdSize != NULL);
    assert(keySize >= 0 && *mdSize >= 0);
    assert(key != NULL || keySize == 0);
    assert(source != NULL || sourceSize == 0);

    ERR_clear_error();

    // OpenSSL in FIPS mode enforces a minimum key size for HMAC. .NET allows algorithms to be used
    // for any key size, regardless of FIPS, and does not enforce by policy. We zero-extend the HMAC
    // key so that OpenSSL believes the key is always of acceptable length.

    // If the keySize is greater than or equal to the block size, then we don't need to perform any zero extension.
    // If for whatever reason the provider does not return a block size, pass it through.
    // The supported hashes are a closed set, MD5, SHA-1, SHA-2, and SHA-3.
    // SHA-3-256 has the largest known block size of 136 bytes. If the block size is somehow bigger, we don't zero
    // extend the key.
    // We also use the adjusted buffer if our source key is NULL, as OpenSSL does not accept NULL even if the
    // keySize is zero. This is done implicitly if the keySize is zero.

    int blockSize = EVP_MD_get_block_size(type);
    uint8_t keyBuffer[HMAC_MAX_BLOCK_SIZE];
    unsigned int keyBufferClearSize;
    const uint8_t* usableKey;
    int32_t usableKeySize;

    if (keySize < blockSize && HMAC_MAX_BLOCK_SIZE >= blockSize && blockSize > 0)
    {
        unsigned int unsignedKeySize = Int32ToUint32(keySize);
        usableKeySize = blockSize;
        usableKey = keyBuffer;
        keyBufferClearSize = unsignedKeySize;
        memset(keyBuffer + unsignedKeySize, 0, (sizeof(uint8_t) * HMAC_MAX_BLOCK_SIZE) - unsignedKeySize);
        memcpy(keyBuffer, key, unsignedKeySize);
    }
    else
    {
        keyBufferClearSize = 0;
        usableKeySize = keySize;
        usableKey = key;
    }

    unsigned int unsignedSource = Int32ToUint32(sourceSize);
    unsigned int unsignedSize = Int32ToUint32(*mdSize);
    unsigned char* result = HMAC(type, usableKey, usableKeySize, source, unsignedSource, md, &unsignedSize);
    *mdSize = Uint32ToInt32(unsignedSize);

    if (keyBufferClearSize > 0)
    {
        OPENSSL_cleanse(keyBuffer, keyBufferClearSize);
    }

    return result == NULL ? 0 : 1;
}
