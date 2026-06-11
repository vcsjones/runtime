// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;

namespace System.Security.Cryptography
{
    internal sealed class Ed25519Implementation : Ed25519
    {
        private SafeEvpPKeyHandle _key;
        private readonly bool _hasPrivate;

        internal static new bool IsSupported { get; } = Interop.Crypto.Ed25519Available();

        internal SafeEvpPKeyHandle Key => _key;

        private Ed25519Implementation(SafeEvpPKeyHandle key, bool hasPrivate)
        {
            Debug.Assert(key is not null);
            Debug.Assert(!key.IsInvalid);

            _key = key;
            _hasPrivate = hasPrivate;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _key?.Dispose();
                _key = null!;
            }

            base.Dispose(disposing);
        }

        internal static Ed25519Implementation GenerateKeyImpl()
        {
            Debug.Assert(IsSupported);
            SafeEvpPKeyHandle key = Interop.Crypto.Ed25519GenerateKey();
            Debug.Assert(!key.IsInvalid);
            return new Ed25519Implementation(key, hasPrivate: true);
        }

        internal static Ed25519Implementation ImportPrivateKeyImpl(ReadOnlySpan<byte> source)
        {
            Debug.Assert(IsSupported);
            SafeEvpPKeyHandle key = Interop.Crypto.Ed25519ImportPrivateKey(source);
            Debug.Assert(!key.IsInvalid);
            return new Ed25519Implementation(key, hasPrivate: true);
        }

        internal static Ed25519Implementation ImportPublicKeyImpl(ReadOnlySpan<byte> source)
        {
            Debug.Assert(IsSupported);
            SafeEvpPKeyHandle key = Interop.Crypto.Ed25519ImportPublicKey(source);
            Debug.Assert(!key.IsInvalid);
            return new Ed25519Implementation(key, hasPrivate: false);
        }

        protected override void ExportPrivateKeyCore(Span<byte> destination)
        {
            Debug.Assert(destination.Length == PrivateKeySizeInBytes);

            if (!_hasPrivate)
            {
                throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);
            }

            Interop.Crypto.Ed25519ExportPrivateKey(_key, destination);
        }

        protected override void ExportPublicKeyCore(Span<byte> destination)
        {
            Debug.Assert(destination.Length == PublicKeySizeInBytes);
            Interop.Crypto.Ed25519ExportPublicKey(_key, destination);
        }

        protected override void SignDataCore(ReadOnlySpan<byte> data, Span<byte> destination)
        {
            Debug.Assert(destination.Length == SignatureSizeInBytes);

            if (!_hasPrivate)
            {
                throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);
            }

            Interop.Crypto.Ed25519SignData(_key, data, destination);
        }

        protected override bool VerifyDataCore(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        {
            Debug.Assert(signature.Length == SignatureSizeInBytes);
            return Interop.Crypto.Ed25519VerifyData(_key, data, signature);
        }
    }
}
