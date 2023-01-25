// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "pal_evp_pkey_eddsa.h"

#include <assert.h>

EVP_PKEY* CryptoNative_Ed25519GenerateKey()
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
