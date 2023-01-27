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
        [LibraryImport(Libraries.CryptoNative)]
        private static partial SafeEvpPKeyHandle CryptoNative_Ed25519GenerateKey();

        [LibraryImport(Libraries.CryptoNative)]
        private static unsafe partial int CryptoNative_EdDsaExportPublicKey(
            SafeEvpPKeyHandle pKey,
            byte* publicKeyBuffer,
            int publicKeyBufferLength,
            out int publicKeyWritten);

        [LibraryImport(Libraries.CryptoNative)]
        private static unsafe partial int CryptoNative_EdDsaExportPrivateKey(
            SafeEvpPKeyHandle pKey,
            byte* privateKeyBuffer,
            int privateKeyBufferLength,
            out int privateKeyWritten);

        [LibraryImport(Libraries.CryptoNative)]
        private static unsafe partial SafeEvpPKeyHandle CryptoNative_Ed25519ImportPublicKey(
            byte* publicKey,
            int publicKeyLength);

        [LibraryImport(Libraries.CryptoNative)]
        private static unsafe partial SafeEvpPKeyHandle CryptoNative_Ed25519ImportPrivateKey(
            byte* privateKey,
            int privateKeyLength);

        [LibraryImport(Libraries.CryptoNative)]
        private static unsafe partial int CryptoNative_EdDsaSignData(
            SafeEvpPKeyHandle pKey,
            byte* data,
            int dataLength,
            byte* signatureBuffer,
            int signatureBufferLength,
            out int signatureWritten);

        [LibraryImport(Libraries.CryptoNative)]
        private static unsafe partial int CryptoNative_EdDsaVerifyData(
            SafeEvpPKeyHandle pKey,
            byte* data,
            int dataLength,
            byte* signature,
            int signatureLength,
            out int isValidSignature);

        internal static unsafe bool EdDsaVerifyData(
            SafeEvpPKeyHandle pKey,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> signature)
        {
            fixed (byte* pData = data)
            fixed (byte* pSignature = signature)
            {
                const int Success = 1;
                const int ValidSignature = 1;
                int ret = CryptoNative_EdDsaVerifyData(
                    pKey,
                    pData,
                    data.Length,
                    pSignature,
                    signature.Length,
                    out int isValidSignature);

                if (ret == Success)
                {
                    Debug.Assert(isValidSignature is 0 or 1);
                    return isValidSignature == ValidSignature;
                }
                else
                {
                    Debug.Assert(ret == 0);
                    throw CreateOpenSslCryptographicException();
                }
            }
        }

        internal static unsafe bool TryEdDsaSignData(
            SafeEvpPKeyHandle pKey,
            ReadOnlySpan<byte> data,
            Span<byte> signatureBuffer,
            out int signatureWritten)
        {
            fixed (byte* pData = data)
            fixed (byte* pSignatureBuffer = signatureBuffer)
            {
                int ret = CryptoNative_EdDsaSignData(
                    pKey,
                    pData,
                    data.Length,
                    pSignatureBuffer,
                    signatureBuffer.Length,
                    out int written);

                const int Success = 1;
                const int BufferTooSmall = -1;
                const int Error = 0;

                switch (ret)
                {
                    case Success:
                        signatureWritten = written;
                        return true;
                    case BufferTooSmall:
                        signatureWritten = 0;
                        return false;
                    case Error:
                        throw CreateOpenSslCryptographicException();
                    default:
                        Debug.Fail($"Unexpected result from native shim {nameof(CryptoNative_EdDsaSignData)}: {ret}");
                        throw new CryptographicException();
                }
            }
        }

        internal static unsafe SafeEvpPKeyHandle Ed25519ImportPublicKey(ReadOnlySpan<byte> publicKey)
        {
            fixed (byte* pPublicKey = publicKey)
            {
                SafeEvpPKeyHandle pKey = CryptoNative_Ed25519ImportPublicKey(pPublicKey, publicKey.Length);

                if (pKey.IsInvalid)
                {
                    Exception ex = CreateOpenSslCryptographicException();
                    pKey.Dispose();
                    throw ex;
                }

                return pKey;
            }
        }

        internal static unsafe SafeEvpPKeyHandle Ed25519ImportPrivateKey(ReadOnlySpan<byte> privateKey)
        {
            fixed (byte* pPrivateKey = privateKey)
            {
                SafeEvpPKeyHandle pKey = CryptoNative_Ed25519ImportPrivateKey(pPrivateKey, privateKey.Length);

                if (pKey.IsInvalid)
                {
                    Exception ex = CreateOpenSslCryptographicException();
                    pKey.Dispose();
                    throw ex;
                }

                return pKey;
            }
        }

        internal static unsafe bool TryEdDsaExportPublicKey(SafeEvpPKeyHandle pKey, Span<byte> publicKeyBuffer, out int bytesWritten)
        {
            fixed (byte* pPublicKeyBuffer = publicKeyBuffer)
            {
                int ret = CryptoNative_EdDsaExportPublicKey(
                    pKey,
                    pPublicKeyBuffer,
                    publicKeyBuffer.Length,
                    out int publicKeyWritten);

                const int Success = 1;
                const int BufferTooSmall = -1;
                const int Error = 0;

                switch (ret)
                {
                    case Success:
                        bytesWritten = publicKeyWritten;
                        return true;
                    case BufferTooSmall:
                        bytesWritten = 0;
                        return false;
                    case Error:
                        bytesWritten = 0;
                        throw CreateOpenSslCryptographicException();
                    default:
                        Debug.Fail($"Unexpected result from native shim {nameof(CryptoNative_EdDsaExportPublicKey)}: {ret}");
                        throw new CryptographicException();
                }
            }
        }

        internal static unsafe bool TryEdDsaExportPrivateKey(SafeEvpPKeyHandle pKey, Span<byte> privateKeyBuffer, out int bytesWritten)
        {
            fixed (byte* pPrivateKeyBuffer = privateKeyBuffer)
            {
                int ret = CryptoNative_EdDsaExportPrivateKey(
                    pKey,
                    pPrivateKeyBuffer,
                    privateKeyBuffer.Length,
                    out int privateKeyWritten);

                const int Success = 1;
                const int BufferTooSmall = -1;
                const int Error = 0;

                switch (ret)
                {
                    case Success:
                        bytesWritten = privateKeyWritten;
                        return true;
                    case BufferTooSmall:
                        bytesWritten = 0;
                        return false;
                    case Error:
                        bytesWritten = 0;
                        throw CreateOpenSslCryptographicException();
                    default:
                        Debug.Fail($"Unexpected result from native shim {nameof(CryptoNative_EdDsaExportPrivateKey)}: {ret}");
                        throw new CryptographicException();
                }
            }
        }

        internal static SafeEvpPKeyHandle Ed25519GenerateKey()
        {
            SafeEvpPKeyHandle pKey = CryptoNative_Ed25519GenerateKey();

            if (pKey.IsInvalid)
            {
                Exception ex = CreateOpenSslCryptographicException();
                pKey.Dispose();
                throw ex;
            }

            return pKey;
        }
    }
}
