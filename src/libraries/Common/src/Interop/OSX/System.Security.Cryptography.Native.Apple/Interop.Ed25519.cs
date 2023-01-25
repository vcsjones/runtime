// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Apple;

internal static partial class Interop
{
    internal static partial class AppleCrypto
    {
        internal static unsafe void Ed25519Generate(
            Span<byte> privateKeyDestination,
            Span<byte> publicKeyDestination,
            out int privateKeyWritten,
            out int publicKeyWritten)
        {
            fixed (byte* pPrivateKey = privateKeyDestination)
            fixed (byte* pPublicKey = publicKeyDestination)
            {
                int result = AppleCryptoNative_Ed25519Generate(
                    pPrivateKey,
                    privateKeyDestination.Length,
                    pPublicKey,
                    publicKeyDestination.Length,
                    out privateKeyWritten,
                    out publicKeyWritten);

                const int Success = 1;

                if (result != Success)
                {
                    CryptographicOperations.ZeroMemory(privateKeyDestination);
                    throw new CryptographicException();
                }
            }
        }

        internal static unsafe int Ed25519Sign(
            ReadOnlySpan<byte> privateKey,
            ReadOnlySpan<byte> data,
            Span<byte> destination)
        {
            fixed (byte* pPrivateKey = privateKey)
            fixed (byte* pData = data)
            fixed (byte* pDestination = destination)
            {
                const int Success = 1;

                int result = AppleCryptoNative_Ed25519Sign(
                    pPrivateKey,
                    privateKey.Length,
                    pData,
                    data.Length,
                    pDestination,
                    destination.Length,
                    out int signatureWritten);

                if (result != Success)
                {
                    throw new CryptographicException();
                }

                return signatureWritten;
            }
        }

        internal static unsafe bool Ed25519Verify(
            ReadOnlySpan<byte> publicKey,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> signature)
        {
            fixed (byte* pPublicKey = publicKey)
            fixed (byte* pData = data)
            fixed (byte* pSignature = signature)
            {
                const int Success = 1;
                const int ValidSignature = 1;
                int result = AppleCryptoNative_Ed25519Verify(
                    pPublicKey,
                    publicKey.Length,
                    pData,
                    data.Length,
                    pSignature,
                    signature.Length,
                    out int validationResult);

                if (result != Success)
                {
                    throw new CryptographicException();
                }

                return validationResult == ValidSignature;
            }
        }

        internal static unsafe bool Ed25519ValidPublicKey(ReadOnlySpan<byte> publicKey)
        {
            fixed (byte* pPublicKey = publicKey)
            {
                const int ValidKey = 1;
                int result = AppleCryptoNative_Ed25519ValidPublicKey(pPublicKey, publicKey.Length);
                return result == ValidKey;
            }
        }

        internal static unsafe bool Ed25519ValidPrivateKey(
            ReadOnlySpan<byte> privateKey,
            Span<byte> publicKey,
            out int publicKeyWritten)
        {
            fixed (byte* pPrivateKey = privateKey)
            fixed (byte* pPublicKey = publicKey)
            {
                const int Success = 1;
                const int ValidPrivateKey = 1;
                int result = AppleCryptoNative_Ed25519ValidPrivateKey(
                    pPrivateKey,
                    privateKey.Length,
                    pPublicKey,
                    publicKey.Length,
                    out publicKeyWritten,
                    out int isValidPrivateKey);

                if (result != Success)
                {
                    throw new CryptographicException();
                }

                return isValidPrivateKey == ValidPrivateKey;
            }
        }

        [LibraryImport(Libraries.AppleCryptoNative)]
        private static unsafe partial int AppleCryptoNative_Ed25519Generate(
            byte* privateKeyPtr,
            int privateKeyLength,
            byte* publicKeyPtr,
            int publicKeyLength,
            out int privateKeyWritten,
            out int publicKeyWritten);

        [LibraryImport(Libraries.AppleCryptoNative)]
        private static unsafe partial int AppleCryptoNative_Ed25519Sign(
            byte* privateKeyPtr,
            int privateKeyLength,
            byte* dataPtr,
            int dataLength,
            byte* signaturePtr,
            int signatureLength,
            out int signatureWritten);

        [LibraryImport(Libraries.AppleCryptoNative)]
        private static unsafe partial int AppleCryptoNative_Ed25519Verify(
            byte* publicKeyPtr,
            int publicKeyLength,
            byte* dataPtr,
            int dataLength,
            byte* signaturePtr,
            int signatureLength,
            out int validSignature);

        [LibraryImport(Libraries.AppleCryptoNative)]
        private static unsafe partial int AppleCryptoNative_Ed25519ValidPublicKey(
            byte* publicKeyPtr,
            int publicKeyLength);

        [LibraryImport(Libraries.AppleCryptoNative)]
        private static unsafe partial int AppleCryptoNative_Ed25519ValidPrivateKey(
            byte* privateKeyPtr,
            int privateKeyLength,
            byte* publicKeyPtr,
            int publicKeyLength,
            out int publicKeyWritten,
            out int validPrivateKey);
    }
}
