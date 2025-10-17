// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "pal_config.h"
#include "pal_utilities.h"
#include "pal_hmac.h"

#include <assert.h>

static EVP_MAC* g_evpMacHmac = NULL;
static pthread_once_t g_evpMacHmacInit = PTHREAD_ONCE_INIT;

static void EnsureMacHmac(void)
{
    // This should not be called directly, it should be called by pthread_once.
#ifdef NEED_OPENSSL_3_0
    if (API_EXISTS(EVP_MAC_fetch))
    {
        g_evpMacHmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
        return;
    }
#endif

    g_evpMacHmac = NULL;
}

#define ENSURE_DN_MAC_CONSISTENCY(ctx) \
    do \
    { \
        assert(ctx && ((ctx->legacy == NULL) != (ctx->mac == NULL))); \
    } \
    while (0)

static const uint8_t* GetContextKey(const DN_MAC_CTX* ctx, size_t* len)
{
    assert(len);

    if (!ctx->hasKey)
    {
        *len = 0;
        return NULL;
    }

    *len = ctx->keyLen;
    return (const uint8_t*)(((const uint8_t*)ctx) + sizeof(DN_MAC_CTX));
}

static DN_MAC_CTX* CreateEmptyContext(const uint8_t* key, size_t keyLenT)
{
    const size_t ctxSize = sizeof(DN_MAC_CTX);
    size_t bufferSize = ctxSize;
    assert(key || keyLenT == 0);

    unsigned long version = OpenSSL_version_num();
    bool copyKey = false;

    // OpenSSL [3.0.0, 3.0.2] have an issue where EVP_MAC_init cannot reset the HMAC instance
    // with its existing key. The key must always be supplied. In order to work around this,
    // we keep a copy of the key for these OpenSSL versions.
    // If this is on a fixed or non-applicable version of OpenSSL, the key in the context struct will be
    // NULL. A NULL key tells the init to re-use the existing key properly. So for affected versions of
    // OpenSSL, the key will be present. For unaffected, it will be NULL and let OpenSSL do the correct reset
    // behavior.
    if (version >= OPENSSL_VERSION_3_0_RTM && version <= OPENSSL_VERSION_3_0_2_RTM)
    {
        if (SIZE_MAX < INT32_MAX || (SIZE_MAX - keyLenT < ctxSize))
        {
            // In practice this should not happen. It would mean the Linux distro is not 32 or 64-bit, or was built
            // with a lower SIZE_T. Still, we want to avoid signed arithmetic overflow since that is UB.
            return NULL;
        }

        bufferSize += keyLenT;
        copyKey = true;
    }

    DN_MAC_CTX* dnctx = (DN_MAC_CTX*)malloc(bufferSize);

    if (dnctx == NULL)
    {
        return NULL;
    }

    memset(dnctx, 0, ctxSize);

    if (copyKey)
    {
        dnctx->hasKey = true;
        dnctx->keyLen = keyLenT;

        if (key && keyLenT > 0)
        {
            memcpy(((uint8_t*)dnctx) + ctxSize, key, keyLenT);
        }
    }
    else
    {
        dnctx->hasKey = false;
    }

    return dnctx;
}

static void ClearFreeContext(DN_MAC_CTX* dnctx)
{
    // This only zeros the context and key. The actual contexts must have been freed and explicitly NULLed before
    // reaching here.
    assert(!dnctx->legacy);
    assert(!dnctx->mac);

    OPENSSL_cleanse(dnctx, sizeof(DN_MAC_CTX) + dnctx->keyLen);
    free(dnctx);
}

DN_MAC_CTX* CryptoNative_HmacCreate(uint8_t* key, int32_t keyLen, const EVP_MD* md)
{
    assert(key != NULL || keyLen == 0);
    assert(keyLen >= 0);
    assert(md != NULL);

    pthread_once(&g_evpMacHmacInit, EnsureMacHmac);
    ERR_clear_error();
    size_t keyLenT = Int32ToSizeT(keyLen);

    // NOTE: We can't pass NULL as empty key since HMAC_Init_ex and EVP_MAC_init will interpret
    // that as request to reuse the "existing" key.
    uint8_t _ = 0;
    if (keyLenT == 0)
    {
        key = &_;
    }

    DN_MAC_CTX* dnctx = CreateEmptyContext(key, keyLenT);

    if (dnctx == NULL)
    {
        ERR_put_error(ERR_LIB_EVP, 0, ERR_R_MALLOC_FAILURE, __FILE__, __LINE__);
        return NULL;
    }

#ifdef NEED_OPENSSL_3_0
    // HMAC-MD5 on some Linux distros is not supported at all for EVP_MAC. In this case we will fall back to the legacy API
    // for all HMAC-MD5 uses.
    if (g_evpMacHmac != NULL && !EVP_MD_is_a(md, "MD5"))
    {
        EVP_MAC_CTX* evpMac = EVP_MAC_CTX_new(g_evpMacHmac);

        if (evpMac == NULL)
        {
            ClearFreeContext(dnctx);
            return NULL;
        }

        const char* algorithm = EVP_MD_get0_name(md);

        // OSSL_PARAM_construct_utf8_string wants a non-const qualified value. Rather than suppress compiler warnings
        // which differ from compiler to compiler, we copy the string in to a temporary value.
        char* algorithmDup = strdup(algorithm);

        if (algorithmDup == NULL)
        {
            EVP_MAC_CTX_free(evpMac);
            ClearFreeContext(dnctx);
            return NULL;
        }

        OSSL_PARAM params[] =
        {
            OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, (void*) key, keyLenT),
            OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, algorithmDup, 0),
            OSSL_PARAM_construct_end(),
        };

        if (!EVP_MAC_init(evpMac, NULL, 0, params))
        {
            EVP_MAC_CTX_free(evpMac);
            ClearFreeContext(dnctx);
            free(algorithmDup);
            return NULL;
        }

        free(algorithmDup);
        dnctx->mac = evpMac;
        return dnctx;
    }
    else
#endif
    {
        HMAC_CTX* ctx = HMAC_CTX_new();

        if (ctx == NULL)
        {
            ERR_put_error(ERR_LIB_EVP, 0, ERR_R_MALLOC_FAILURE, __FILE__, __LINE__);
            ClearFreeContext(dnctx);
            return NULL;
        }

        int ret = HMAC_Init_ex(ctx, key, keyLen, md, NULL);

        if (!ret)
        {
            HMAC_CTX_free(ctx);
            ClearFreeContext(dnctx);
            return NULL;
        }

        dnctx->legacy = ctx;
        return dnctx;
    }
}

void CryptoNative_HmacDestroy(DN_MAC_CTX* ctx)
{
    if (ctx != NULL)
    {
        ENSURE_DN_MAC_CONSISTENCY(ctx);

#ifdef NEED_OPENSSL_3_0
        if (ctx->mac)
        {
            EVP_MAC_CTX_free(ctx->mac);
            ctx->mac = NULL;
        }
#endif
        if (ctx->legacy)
        {
            HMAC_CTX_free(ctx->legacy);
            ctx->legacy = NULL;
        }

        ClearFreeContext(ctx);
    }
}

int32_t CryptoNative_HmacReset(DN_MAC_CTX* ctx)
{
    ENSURE_DN_MAC_CONSISTENCY(ctx);
    ERR_clear_error();

#ifdef NEED_OPENSSL_3_0
    if (ctx->mac)
    {
        size_t keySize = 0;
        const uint8_t* key = GetContextKey(ctx, &keySize);
        return EVP_MAC_init(ctx->mac, key, keySize, NULL);
    }
#endif

    if (ctx->legacy)
    {
        return HMAC_Init_ex(ctx->legacy, NULL, 0, NULL, NULL);
    }

    return -1;
}

int32_t CryptoNative_HmacUpdate(DN_MAC_CTX* ctx, const uint8_t* data, int32_t len)
{
    ENSURE_DN_MAC_CONSISTENCY(ctx);
    assert(data != NULL || len == 0);
    assert(len >= 0);

    ERR_clear_error();

    if (len < 0)
    {
        return 0;
    }

    uint8_t _ = 0;

    if (len == 0)
    {
        data = &_;
    }

#ifdef NEED_OPENSSL_3_0
    if (ctx->mac)
    {
        return EVP_MAC_update(ctx->mac, data, Int32ToSizeT(len));
    }
#endif

    if (ctx->legacy)
    {
        return HMAC_Update(ctx->legacy, data, Int32ToSizeT(len));
    }

    return -1;
}

int32_t CryptoNative_HmacFinal(DN_MAC_CTX* ctx, uint8_t* md, int32_t* len)
{
    ENSURE_DN_MAC_CONSISTENCY(ctx);
    assert(len != NULL);
    assert(md != NULL || *len == 0);
    assert(*len >= 0);

    ERR_clear_error();

    if (len == NULL || *len < 0)
    {
        return 0;
    }

    int ret = -1;

#ifdef NEED_OPENSSL_3_0
    if (ctx->mac)
    {
        size_t outl = 0;
        size_t lenT = Int32ToSizeT(*len);
        ret = EVP_MAC_final(ctx->mac, md, &outl, lenT);
        *len = SizeTToInt32(outl);
        return ret;
    }
#endif

    if (ctx->legacy)
    {
        unsigned int unsignedLen = Int32ToUint32(*len);
        ret = HMAC_Final(ctx->legacy, md, &unsignedLen);
        *len = Uint32ToInt32(unsignedLen);
        return ret;
    }

    return ret;
}

DN_MAC_CTX* CryptoNative_HmacCopy(const DN_MAC_CTX* ctx)
{
    ENSURE_DN_MAC_CONSISTENCY(ctx);
    ERR_clear_error();

    size_t keyLen = 0;
    const uint8_t* key = GetContextKey(ctx, &keyLen);
    DN_MAC_CTX* dupctx = CreateEmptyContext(key, keyLen);

    if (dupctx == NULL)
    {
        return NULL;
    }

#ifdef NEED_OPENSSL_3_0
    if (ctx->mac)
    {
        EVP_MAC_CTX* macDup = EVP_MAC_CTX_dup(ctx->mac);

        if (macDup == NULL)
        {
            ClearFreeContext(dupctx);
            return NULL;
        }

        dupctx->mac = macDup;
        return dupctx;
    }
#endif

    if (ctx->legacy)
    {
        HMAC_CTX* dup = HMAC_CTX_new();

        if (dup == NULL)
        {
            ERR_put_error(ERR_LIB_EVP, 0, ERR_R_MALLOC_FAILURE, __FILE__, __LINE__);
            ClearFreeContext(dupctx);
            return NULL;
        }

    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcast-qual"
        if (!HMAC_CTX_copy(dup, (HMAC_CTX*)(ctx->legacy)))
    #pragma clang diagnostic pop
        {
            ClearFreeContext(dupctx);
            HMAC_CTX_free(dup);
            return NULL;
        }

        dupctx->legacy = dup;
        return dupctx;
    }

    ClearFreeContext(dupctx);
    return NULL;
}

int32_t CryptoNative_HmacCurrent(const DN_MAC_CTX* ctx, uint8_t* md, int32_t* len)
{
    ENSURE_DN_MAC_CONSISTENCY(ctx);
    assert(len != NULL);
    assert(md != NULL || *len == 0);
    assert(*len >= 0);

    ERR_clear_error();

    if (len == NULL || *len < 0)
    {
        return 0;
    }

    DN_MAC_CTX* dup = CryptoNative_HmacCopy(ctx);

    if (dup != NULL)
    {
        int ret = CryptoNative_HmacFinal(dup, md, len);
        CryptoNative_HmacDestroy(dup);
        return ret;
    }

    *len = 0;
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

    uint8_t empty = 0;

    if (key == NULL)
    {
        if (keySize != 0)
        {
            return -1;
        }

        key = &empty;
    }

    unsigned int unsignedSource = Int32ToUint32(sourceSize);
    unsigned int unsignedSize = Int32ToUint32(*mdSize);
    unsigned char* result = HMAC(type, key, keySize, source, unsignedSource, md, &unsignedSize);
    *mdSize = Uint32ToInt32(unsignedSize);

    return result == NULL ? 0 : 1;
}
