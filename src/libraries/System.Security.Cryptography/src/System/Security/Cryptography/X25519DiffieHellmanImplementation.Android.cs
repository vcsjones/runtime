// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Security.Cryptography
{
    internal sealed class X25519DiffieHellmanImplementation : X25519DiffieHellman
    {
        private readonly SafeX25519PublicKeyHandle _publicKey;
        private readonly SafeX25519PrivateKeyHandle? _privateKey;

        internal static new bool IsSupported { get; } = Interop.AndroidCrypto.X25519IsSupported();

        private X25519DiffieHellmanImplementation(SafeX25519PublicKeyHandle publicKey, SafeX25519PrivateKeyHandle? privateKey)
        {
            _publicKey = publicKey;
            _privateKey = privateKey;
        }

        protected override void DeriveRawSecretAgreementCore(X25519DiffieHellman otherParty, Span<byte> destination)
        {
            throw new NotImplementedException();
        }

        protected override void ExportPrivateKeyCore(Span<byte> destination)
        {
            throw new NotImplementedException();
        }

        protected override void ExportPublicKeyCore(Span<byte> destination)
        {
            throw new NotImplementedException();
        }

        protected override bool TryExportPkcs8PrivateKeyCore(Span<byte> destination, out int bytesWritten)
        {
            throw new NotImplementedException();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _publicKey.Dispose();
                _privateKey?.Dispose();
            }

            base.Dispose(disposing);
        }

        internal static X25519DiffieHellmanImplementation GenerateKeyImpl()
        {
            Interop.AndroidCrypto.X25519GenerateKey(
                out SafeX25519PublicKeyHandle publicKey,
                out SafeX25519PrivateKeyHandle privateKey);

            return new X25519DiffieHellmanImplementation(publicKey, privateKey);
        }

        internal static X25519DiffieHellmanImplementation ImportPrivateKeyImpl(ReadOnlySpan<byte> source)
        {
            throw new NotImplementedException();
        }

        internal static X25519DiffieHellmanImplementation ImportPublicKeyImpl(ReadOnlySpan<byte> source)
        {
            throw new NotImplementedException();
        }
    }
}
