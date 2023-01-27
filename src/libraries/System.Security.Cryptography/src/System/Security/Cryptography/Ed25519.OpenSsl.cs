// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Versioning;

namespace System.Security.Cryptography
{
    public sealed class Ed25519OpenSsl : Ed25519
    {
        private SafeEvpPKeyHandle? _pKey;
        private bool _disposed;

        internal Ed25519OpenSsl()
        {
        }

        [UnsupportedOSPlatform("android")]
        [UnsupportedOSPlatform("browser")]
        [UnsupportedOSPlatform("ios")]
        [UnsupportedOSPlatform("tvos")]
        [UnsupportedOSPlatform("windows")]
        public Ed25519OpenSsl(SafeEvpPKeyHandle pkeyHandle)
        {
            ArgumentNullException.ThrowIfNull(pkeyHandle);

            if (pkeyHandle.IsInvalid)
                throw new ArgumentException(SR.Cryptography_OpenInvalidHandle, nameof(pkeyHandle));

            ThrowIfNotSupported();

            SafeEvpPKeyHandle newKey = Interop.Crypto.EvpPKeyDuplicate(
                pkeyHandle,
                Interop.Crypto.EvpAlgorithmId.Ed25519);

            Debug.Assert(!newKey.IsInvalid);
            _pKey = newKey;
        }

        public override bool HasPrivateKey
        {
            get
            {
                CheckDisposed();
                GenerateKeyIfNeeded();

                return Interop.Crypto.EdDsaHasPrivateKey(_pKey);
            }
        }

        [MemberNotNull(nameof(_pKey))]
        public override void GenerateKey()
        {
            CheckDisposed();
            ClearKeys();
            _pKey = Interop.Crypto.Ed25519GenerateKey();
            Debug.Assert(!_pKey.IsInvalid);
        }

        protected override int SignDataCore(ReadOnlySpan<byte> data, Span<byte> destination)
        {
            CheckDisposed();
            GenerateKeyIfNeeded();

            Debug.Assert(destination.Length >= SignatureSizeInBytes);

            if (!Interop.Crypto.TryEdDsaSignData(_pKey, data, destination, out int written)
                || written != SignatureSizeInBytes)
            {
                Debug.Fail("Failed to produce a signature or the amount written is unexpected.");
                throw new CryptographicException();
            }

            return written;
        }

        protected override bool VerifyDataCore(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        {
            CheckDisposed();
            GenerateKeyIfNeeded();

            return Interop.Crypto.EdDsaVerifyData(_pKey, data, signature);
        }

        protected override int ExportPrivateKeyCore(Span<byte> destination)
        {
            CheckDisposed();
            GenerateKeyIfNeeded();

            if (!Interop.Crypto.TryEdDsaExportPrivateKey(_pKey, destination, out int written) || written != PrivateKeySize)
            {
                Debug.Fail("Failed to export the pubic key or the amount written is unexpected.");
                throw new CryptographicException();
            }

            return written;
        }

        protected override int ExportPublicKeyCore(Span<byte> destination)
        {
            CheckDisposed();
            GenerateKeyIfNeeded();

            if (!Interop.Crypto.TryEdDsaExportPublicKey(_pKey, destination, out int written) || written != PublicKeySize)
            {
                Debug.Fail("Failed to export the pubic key or the amount written is unpexpected.");
                throw new CryptographicException();
            }

            return written;
        }

        protected override void ImportPublicKeyCore(ReadOnlySpan<byte> publicKey)
        {
            CheckDisposed();
            ClearKeys();

            _pKey = Interop.Crypto.Ed25519ImportPublicKey(publicKey);
        }

        protected override void ImportPrivateKeyCore(ReadOnlySpan<byte> privateKey)
        {
            CheckDisposed();
            ClearKeys();

            _pKey = Interop.Crypto.Ed25519ImportPrivateKey(privateKey);
        }

        private void ClearKeys()
        {
            _pKey?.Dispose();
            _pKey = null;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && !_disposed)
            {
                ClearKeys();
                _disposed = true;
            }
        }

        private void CheckDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

        [MemberNotNull(nameof(_pKey))]
        private void GenerateKeyIfNeeded()
        {
            if (_pKey is null)
            {
                _pKey = Interop.Crypto.Ed25519GenerateKey();
                Debug.Assert(!_pKey.IsInvalid);
            }
        }

        private static void ThrowIfNotSupported()
        {
            if (!Interop.OpenSslNoInit.OpenSslIsAvailable)
            {
                throw new PlatformNotSupportedException(SR.Format(SR.Cryptography_AlgorithmNotSupported, nameof(Ed25519OpenSsl)));
            }
        }
    }
}
