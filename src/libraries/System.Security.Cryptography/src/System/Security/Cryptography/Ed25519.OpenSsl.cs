// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Versioning;

namespace System.Security.Cryptography
{
    public abstract partial class Ed25519
    {
        public static new partial Ed25519 Create() => new Ed25519OpenSsl();
    }

    internal sealed class Ed25519OpenSsl : Ed25519
    {
        private SafeEvpPKeyHandle? _pKey;
        private bool _disposed;

        internal Ed25519OpenSsl()
        {
        }

        [MemberNotNull(nameof(_pKey))]
        public override void GenerateKey()
        {
            CheckDisposed();
            _pKey = Interop.Crypto.Ed25519GenerateKey();
            Debug.Assert(!_pKey.IsInvalid);
        }

        protected override bool TrySignDataCore(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten)
        {
            throw new NotImplementedException();
        }

        protected override bool VerifyDataCore(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        {
            throw new NotImplementedException();
        }

        public override byte[] ExportPrivateKey()
        {
            throw new NotImplementedException();
        }

        public override byte[] ExportPublicKey()
        {
            throw new NotImplementedException();
        }

        public override void ImportPublicKey(ReadOnlySpan<byte> publicKey)
        {
            throw new NotImplementedException();
        }

        public override void ImportPrivateKey(ReadOnlySpan<byte> privateKey)
        {
            throw new NotImplementedException();
        }

        private void ClearKeys()
        {
            _pKey?.Dispose();
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
    }
}
