// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "pal_x25519.h"
#include "pal_misc.h"

int32_t AndroidCryptoNative_X25519IsSupported(void)
{
    JNIEnv* env = GetJNIEnv();

    jstring algorithmName = make_java_string(env, "X25519");
    jobject keyPairGenerator = (*env)->CallStaticObjectMethod(env, g_keyPairGenClass, g_keyPairGenGetInstanceMethod, algorithmName);
    ReleaseLRef(env, algorithmName);

    if (TryClearJNIExceptions(env))
    {
        ReleaseLRef(env, keyPairGenerator);
        return FAIL;
    }

    // Generating a key pair exercises the full provider path, which catches cases where
    // getInstance succeeds on a stub provider but actual key generation is not implemented.
    jobject keyPair = (*env)->CallObjectMethod(env, keyPairGenerator, g_keyPairGenGenKeyPairMethod);
    ReleaseLRef(env, keyPairGenerator);
    ReleaseLRef(env, keyPair);

    return TryClearJNIExceptions(env) ? FAIL : SUCCESS;
}

void AndroidCryptoNative_X25519DestroyKey(jobject key)
{
    if (key)
    {
        JNIEnv* env = GetJNIEnv();

        if ((*env)->IsInstanceOf(env, key, g_DestroyableClass))
        {
            (*env)->CallVoidMethod(env, key, g_destroy);
            (void)TryClearJNIExceptions(env);
        }

        ReleaseGRef(env, key);
    }
}

int32_t AndroidCryptoNative_X25519GenerateKey(jobject* publicKey, jobject* privateKey)
{
    abort_if_invalid_pointer_argument(publicKey);
    abort_if_invalid_pointer_argument(privateKey);

    *publicKey = NULL;
    *privateKey = NULL;

    JNIEnv* env = GetJNIEnv();

    // Conscrypt's XDH KeyPairGenerator does not support initialize(AlgorithmParameterSpec),
    // so we use "X25519" directly as the algorithm name instead of "XDH" + NamedParameterSpec.
    jstring algorithmName = make_java_string(env, "X25519");
    jobject keyPairGenerator = (*env)->CallStaticObjectMethod(env, g_keyPairGenClass, g_keyPairGenGetInstanceMethod, algorithmName);
    ReleaseLRef(env, algorithmName);

    if (CheckJNIExceptions(env))
    {
        ReleaseLRef(env, keyPairGenerator);
        return FAIL;
    }

    jobject keyPair = (*env)->CallObjectMethod(env, keyPairGenerator, g_keyPairGenGenKeyPairMethod);
    ReleaseLRef(env, keyPairGenerator);

    if (CheckJNIExceptions(env) || !keyPair)
    {
        ReleaseLRef(env, keyPair);
        return FAIL;
    }

    jobject pubKey = (*env)->CallObjectMethod(env, keyPair, g_keyPairGetPublicMethod);
    jobject privKey = (*env)->CallObjectMethod(env, keyPair, g_keyPairGetPrivateMethod);
    ReleaseLRef(env, keyPair);

    if (CheckJNIExceptions(env) || !pubKey || !privKey)
    {
        ReleaseLRef(env, pubKey);
        ReleaseLRef(env, privKey);
        return FAIL;
    }

    *publicKey = ToGRef(env, pubKey);
    *privateKey = ToGRef(env, privKey);
    return SUCCESS;
}
