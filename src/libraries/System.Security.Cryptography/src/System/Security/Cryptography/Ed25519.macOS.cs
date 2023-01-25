// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Versioning;

namespace System.Security.Cryptography
{
    public abstract partial class Ed25519
    {
        public static new partial Ed25519 Create() => new Ed25519CryptoKit();
    }

    internal sealed class Ed25519CryptoKit : Ed25519
    {
        private bool _disposed;
        private byte[]? _privateKey;
        private byte[]? _publicKey;

        internal Ed25519CryptoKit()
        {
        }

        [MemberNotNullWhen(true, nameof(_publicKey))]
        private bool IsInitialized => _publicKey is not null;

        protected override bool TrySignDataCore(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten)
        {
            CheckDisposed();
            GenerateKeyIfNeeded();
            CheckPrivateKey();

            Debug.Assert(destination.Length >= GetSignatureSize());
            bytesWritten = Interop.AppleCrypto.Ed25519Sign(_privateKey, data, destination);
            Debug.Assert(bytesWritten == GetSignatureSize());
            return true;
        }

        protected override bool VerifyDataCore(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        {
            CheckDisposed();
            GenerateKeyIfNeeded();

            return Interop.AppleCrypto.Ed25519Verify(_publicKey, data, signature);
        }

        [MemberNotNull(nameof(_privateKey))]
        [MemberNotNull(nameof(_publicKey))]
        public override void GenerateKey()
        {
            CheckDisposed();
            ClearKeys();

            byte[] privateKey = GC.AllocateArray<byte>(PrivateKeySize, pinned: true);
            byte[] publicKey = new byte[PublicKeySize];

            Interop.AppleCrypto.Ed25519Generate(
                privateKey,
                publicKey,
                out int privateKeyWritten,
                out int publicKeyWritten);

            if (privateKeyWritten != PrivateKeySize || publicKeyWritten != PublicKeySize)
            {
                throw new CryptographicException();
            }

            _privateKey = privateKey;
            _publicKey = publicKey;
        }

        public override byte[] ExportPrivateKey()
        {
            CheckDisposed();
            GenerateKeyIfNeeded();
            CheckPrivateKey();

            byte[] privateKey = GC.AllocateArray<byte>(PrivateKeySize, pinned: true);
            _privateKey.AsSpan().CopyTo(privateKey);
            return privateKey;
        }

        public override byte[] ExportPublicKey()
        {
            CheckDisposed();
            GenerateKeyIfNeeded();

            Debug.Assert(_publicKey is { Length : PublicKeySize });
            return _publicKey.AsSpan().ToArray();
        }

        [MemberNotNull(nameof(_publicKey))]
        public override void ImportPublicKey(ReadOnlySpan<byte> publicKey)
        {
            CheckDisposed();

            if (publicKey.Length != PublicKeySize || !Interop.AppleCrypto.Ed25519ValidPublicKey(publicKey))
            {
                throw new CryptographicException(SR.Cryptography_NotValidPublicKey);
            }

            ClearKeys(); // Clear out the existing keys now that we know the public key is valid.
            _publicKey = publicKey.ToArray();
        }

        public override void ImportPrivateKey(ReadOnlySpan<byte> privateKey)
        {
            CheckDisposed();

            if (privateKey.Length != PrivateKeySize)
            {
                throw new CryptographicException(SR.Cryptography_NotValidPrivateKey);
            }

            byte[] publicKeyBuffer = new byte[PublicKeySize];

            if (!Interop.AppleCrypto.Ed25519ValidPrivateKey(privateKey, publicKeyBuffer, out int publicKeyWritten))
            {
                throw new CryptographicException(SR.Cryptography_NotValidPrivateKey);
            }

            if (publicKeyWritten != PublicKeySize)
            {
                throw new CryptographicException();
            }

            // Don't clear keys until we know the one we are importing are valid.
            ClearKeys();

            byte[] newPrivateKey = GC.AllocateArray<byte>(PrivateKeySize, pinned: true);
            privateKey.CopyTo(newPrivateKey);
            _privateKey = newPrivateKey;
            _publicKey = publicKeyBuffer;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && !_disposed)
            {
                ClearKeys();
                _disposed = true;
            }
        }

        private void ClearKeys()
        {
            CryptographicOperations.ZeroMemory(_privateKey);
            _privateKey = null;
            _publicKey = null;
        }

        [MemberNotNull(nameof(_publicKey))]
        private void GenerateKeyIfNeeded()
        {
            if (!IsInitialized)
            {
                GenerateKey();
            }
        }

        [MemberNotNull(nameof(_privateKey))]
        private void CheckPrivateKey()
        {
            if (_privateKey is null)
            {
                throw new CryptographicException(SR.Cryptography_NoPrivateKey);
            }
        }

        private void CheckDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
    }
}
