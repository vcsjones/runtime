// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

internal static partial class Interop
{
    internal static partial class Crypto
    {
        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_Ed25519Available")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool Ed25519Available();

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_Ed25519ExportPrivateKey")]
        private static partial int Ed25519ExportPrivateKey(
            SafeEvpPKeyHandle key,
            Span<byte> destination,
            int destinationLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_Ed25519ExportPublicKey")]
        private static partial int Ed25519ExportPublicKey(
            SafeEvpPKeyHandle key,
            Span<byte> destination,
            int destinationLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_Ed25519GenerateKey")]
        private static partial SafeEvpPKeyHandle CryptoNative_Ed25519GenerateKey();

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_Ed25519ImportPrivateKey")]
        private static partial SafeEvpPKeyHandle Ed25519ImportPrivateKey(ReadOnlySpan<byte> source, int sourceLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_Ed25519ImportPublicKey")]
        private static partial SafeEvpPKeyHandle Ed25519ImportPublicKey(ReadOnlySpan<byte> source, int sourceLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_Ed25519SignData")]
        private static partial int CryptoNative_Ed25519SignData(
            SafeEvpPKeyHandle key,
            ReadOnlySpan<byte> data,
            int dataLength,
            Span<byte> destination,
            int destinationLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_Ed25519VerifyData")]
        private static partial int CryptoNative_Ed25519VerifyData(
            SafeEvpPKeyHandle key,
            ReadOnlySpan<byte> data,
            int dataLength,
            ReadOnlySpan<byte> signature,
            int signatureLength);

        internal static void Ed25519ExportPrivateKey(SafeEvpPKeyHandle key, Span<byte> destination)
        {
            const int Success = 1;
            const int Fail = 0;

            int ret = Ed25519ExportPrivateKey(key, destination, destination.Length);

            switch (ret)
            {
                case Success:
                    return;
                case Fail:
                    throw CreateOpenSslCryptographicException();
                default:
                    Debug.Fail($"{nameof(Ed25519ExportPrivateKey)} returned '{ret}' unexpectedly.");
                    throw new CryptographicException();
            }
        }

        internal static void Ed25519ExportPublicKey(SafeEvpPKeyHandle key, Span<byte> destination)
        {
            const int Success = 1;
            const int Fail = 0;

            int ret = Ed25519ExportPublicKey(key, destination, destination.Length);

            switch (ret)
            {
                case Success:
                    return;
                case Fail:
                    throw CreateOpenSslCryptographicException();
                default:
                    Debug.Fail($"{nameof(Ed25519ExportPublicKey)} returned '{ret}' unexpectedly.");
                    throw new CryptographicException();
            }
        }

        internal static SafeEvpPKeyHandle Ed25519GenerateKey()
        {
            SafeEvpPKeyHandle key = CryptoNative_Ed25519GenerateKey();
            Debug.Assert(key is not null);

            if (key.IsInvalid)
            {
                Exception ex = CreateOpenSslCryptographicException();
                key.Dispose();
                throw ex;
            }

            return key;
        }

        internal static SafeEvpPKeyHandle Ed25519ImportPrivateKey(ReadOnlySpan<byte> source)
        {
            SafeEvpPKeyHandle key = Ed25519ImportPrivateKey(source, source.Length);
            Debug.Assert(key is not null);

            if (key.IsInvalid)
            {
                Exception ex = CreateOpenSslCryptographicException();
                key.Dispose();
                throw ex;
            }

            return key;
        }

        internal static SafeEvpPKeyHandle Ed25519ImportPublicKey(ReadOnlySpan<byte> source)
        {
            SafeEvpPKeyHandle key = Ed25519ImportPublicKey(source, source.Length);
            Debug.Assert(key is not null);

            if (key.IsInvalid)
            {
                Exception ex = CreateOpenSslCryptographicException();
                key.Dispose();
                throw ex;
            }

            return key;
        }

        internal static void Ed25519SignData(
            SafeEvpPKeyHandle key,
            ReadOnlySpan<byte> data,
            Span<byte> destination)
        {
            Debug.Assert(destination.Length == Ed25519.SignatureSizeInBytes);

            int ret = CryptoNative_Ed25519SignData(
                key,
                data,
                data.Length,
                destination,
                destination.Length);

            if (ret != 1)
            {
                throw CreateOpenSslCryptographicException();
            }
        }

        internal static bool Ed25519VerifyData(
            SafeEvpPKeyHandle key,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> signature)
        {
            Debug.Assert(signature.Length == Ed25519.SignatureSizeInBytes);

            int ret = CryptoNative_Ed25519VerifyData(
                key,
                data,
                data.Length,
                signature,
                signature.Length);

            if (ret == 1)
            {
                return true;
            }

            if (ret == 0)
            {
                return false;
            }

            throw CreateOpenSslCryptographicException();
        }
    }
}
