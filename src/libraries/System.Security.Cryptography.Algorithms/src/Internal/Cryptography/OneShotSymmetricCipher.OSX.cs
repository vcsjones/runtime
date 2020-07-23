// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;
using System.Security.Cryptography;
using PAL_ChainingMode = Interop.AppleCrypto.PAL_ChainingMode;
using PAL_SymmetricOperation = Interop.AppleCrypto.PAL_SymmetricOperation;
using PAL_SymmetricAlgorithm = Interop.AppleCrypto.PAL_SymmetricAlgorithm;

namespace Internal.Cryptography
{
    internal static class AppleOneShotSymmetricCipher
    {
        internal static class Aes
        {
            public static int EncryptEcb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext) =>
                Transform(
                    PAL_SymmetricAlgorithm.AES,
                    PAL_ChainingMode.ECB,
                    key,
                    iv: default,
                    plaintext,
                    ciphertext,
                    PAL_SymmetricOperation.Encrypt);

            public static int DecryptEcb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext) =>
                Transform(
                    PAL_SymmetricAlgorithm.AES,
                    PAL_ChainingMode.ECB,
                    key,
                    iv: default,
                    ciphertext,
                    plaintext,
                    PAL_SymmetricOperation.Decrypt);

            public static int EncryptCbc(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext) =>
                Transform(
                    PAL_SymmetricAlgorithm.AES,
                    PAL_ChainingMode.CBC,
                    key,
                    iv,
                    plaintext,
                    ciphertext,
                    PAL_SymmetricOperation.Encrypt);

            public static int DecryptCbc(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext) =>
                Transform(
                    PAL_SymmetricAlgorithm.AES,
                    PAL_ChainingMode.CBC,
                    key,
                    iv,
                    ciphertext,
                    plaintext,
                    PAL_SymmetricOperation.Encrypt);
        }

        private static unsafe int Transform(
            PAL_SymmetricAlgorithm algorithm,
            PAL_ChainingMode chainingMode,
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> iv,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            PAL_SymmetricOperation operation)
        {
            Debug.Assert(key.Length > 0);
            Debug.Assert(chainingMode == PAL_ChainingMode.ECB ^ iv.Length > 0);
            Debug.Assert(output.Length >= input.Length);

            const int Success = 1;
            const int Failed = 0;
            const int InvalidInput = -1;

            int result;
            int dataOutWritten;
            int ccStatus;

            fixed (byte* pKey = key)
            fixed (byte* pIv = iv)
            fixed (byte* pInput = input)
            fixed (byte* pOutput = output)
            {
                result = Interop.AppleCrypto.CryptorOneShot(
                    operation,
                    algorithm,
                    chainingMode,
                    Interop.AppleCrypto.PAL_PaddingMode.None,
                    pKey,
                    key.Length,
                    pIv,
                    pInput,
                    input.Length,
                    pOutput,
                    output.Length,
                    out dataOutWritten,
                    out ccStatus);
            }

            switch (result)
            {
                case Success:
                    return dataOutWritten;
                case Failed:
                    throw Interop.AppleCrypto.CreateExceptionForCCError(
                        ccStatus,
                        Interop.AppleCrypto.CCCryptorStatus);
                case InvalidInput:
                    Debug.Fail($"{nameof(Interop.AppleCrypto.CryptorOneShot)} failed with invalid input");
                    throw new CryptographicException();
                default:
                    Debug.Fail($"{nameof(Interop.AppleCrypto.CryptorOneShot)} returned unknown value.");
                    throw new CryptographicException();
            }
        }
    }
}
