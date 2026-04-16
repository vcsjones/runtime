// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography.Asn1;

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
            ThrowIfPrivateNeeded();

            if (otherParty is X25519DiffieHellmanImplementation otherImpl)
            {
                DeriveRawSecretAgreementCore(_privateKey, otherImpl._publicKey, destination);
            }
            else
            {
                Span<byte> otherPublicKey = stackalloc byte[PublicKeySizeInBytes];
                otherParty.ExportPublicKey(otherPublicKey);

                using (SafeX25519PublicKeyHandle importedPublicKey = ImportPublicKeyAsHandle(otherPublicKey))
                {
                    DeriveRawSecretAgreementCore(_privateKey, importedPublicKey, destination);
                }
            }
        }

        private static void DeriveRawSecretAgreementCore(
            SafeX25519PrivateKeyHandle currentParty,
            SafeX25519PublicKeyHandle otherParty,
            Span<byte> destination)
        {
            Debug.Assert(destination.Length == SecretAgreementSizeInBytes);
            Interop.AndroidCrypto.X25519DeriveSecret(currentParty, otherParty, destination);
        }

        private static SafeX25519PublicKeyHandle ImportPublicKeyAsHandle(ReadOnlySpan<byte> source)
        {
            AsnWriter writer = ExportSubjectPublicKeyInfoCore(source);
            return writer.Encode(static spki => Interop.AndroidCrypto.X25519ImportSubjectPublicKeyInfo(spki));
        }

        protected override void ExportPrivateKeyCore(Span<byte> destination)
        {
            Debug.Assert(destination.Length == PrivateKeySizeInBytes);
            ThrowIfPrivateNeeded();

            // PKCS#8 PrivateKeyInfo for X25519 is small but not strictly fixed-size.
            // 256 bytes leaves ample headroom for typical encodings.
            Span<byte> pkcs8Buffer = stackalloc byte[256];

            if (!Interop.AndroidCrypto.X25519TryExportPkcs8PrivateKey(_privateKey, pkcs8Buffer, out int written))
            {
                Debug.Fail($"X25519 PKCS#8 PrivateKeyInfo did not fit in {pkcs8Buffer.Length} bytes.");
                throw new CryptographicException(SR.Argument_DestinationTooShort);
            }

            try
            {
                KeyFormatHelper.ReadPkcs8(
                    s_knownOids,
                    pkcs8Buffer.Slice(0, written),
                    Pkcs8KeyReader,
                    out int read,
                    out ReadOnlySpan<byte> rawKey);

                if (read != written)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                rawKey.CopyTo(destination);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pkcs8Buffer);
            }

            static void Pkcs8KeyReader(
                ReadOnlySpan<byte> privateKeyContents,
                scoped in ValueAlgorithmIdentifierAsn identifier,
                out ReadOnlySpan<byte> result)
            {
                if (identifier.HasParameters)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                ValueAsnReader reader = new(privateKeyContents, AsnEncodingRules.BER);
                ReadOnlySpan<byte> rawPrivateKey = reader.ReadOctetString();
                reader.ThrowIfNotEmpty();

                if (rawPrivateKey.Length != PrivateKeySizeInBytes)
                {
                    throw new CryptographicException(SR.Argument_PrivateKeyWrongSizeForAlgorithm);
                }

                result = rawPrivateKey;
            }
        }

        protected override void ExportPublicKeyCore(Span<byte> destination)
        {
            Debug.Assert(destination.Length == PublicKeySizeInBytes);

            // An X25519 SubjectPublicKeyInfo is fixed-size and small. If the encoded form
            // does not fit in this buffer, whatever was returned is not an X25519 SPKI.
            Span<byte> spkiBuffer = stackalloc byte[128];

            if (!Interop.AndroidCrypto.X25519TryExportSubjectPublicKeyInfo(_publicKey, spkiBuffer, out int written))
            {
                Debug.Fail($"X25519 SubjectPublicKeyInfo did not fit in {spkiBuffer.Length} bytes.");
                throw new CryptographicException(SR.Argument_DestinationTooShort);
            }

            KeyFormatHelper.ReadSubjectPublicKeyInfo(
                s_knownOids,
                spkiBuffer.Slice(0, written),
                SubjectPublicKeyReader,
                out int read,
                out ReadOnlySpan<byte> rawKey);

            if (read != written)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            rawKey.CopyTo(destination);

            static void SubjectPublicKeyReader(
                ReadOnlySpan<byte> key,
                scoped in ValueAlgorithmIdentifierAsn identifier,
                out ReadOnlySpan<byte> result)
            {
                if (identifier.HasParameters)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                if (key.Length != PublicKeySizeInBytes)
                {
                    throw new CryptographicException(SR.Argument_PublicKeyWrongSizeForAlgorithm);
                }

                result = key;
            }
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
            Debug.Assert(source.Length == PublicKeySizeInBytes);
            return new X25519DiffieHellmanImplementation(ImportPublicKeyAsHandle(source), privateKey: null);
        }

        [MemberNotNull(nameof(_privateKey))]
        private void ThrowIfPrivateNeeded()
        {
            if (_privateKey is null)
            {
                throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);
            }
        }
    }
}
