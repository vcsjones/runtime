// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Text;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.Tests
{
    public abstract class X25519DiffieHellmanBaseTests
    {
        private static readonly PbeParameters s_aes128Pbe = new(PbeEncryptionAlgorithm.Aes128Cbc, HashAlgorithmName.SHA256, 2);

        public abstract X25519DiffieHellman GenerateKey();
        public abstract X25519DiffieHellman ImportPrivateKey(ReadOnlySpan<byte> source);
        public abstract X25519DiffieHellman ImportPublicKey(ReadOnlySpan<byte> source);

        [Fact]
        public void ExportPrivateKey_Roundtrip()
        {
            using X25519DiffieHellman xdh = GenerateKey();

            byte[] privateKey = xdh.ExportPrivateKey();
            Assert.True(privateKey.AsSpan().ContainsAnyExcept((byte)0));
            Assert.Equal(X25519DiffieHellman.PrivateKeySizeInBytes, privateKey.Length);

            Span<byte> privateKeySpan = new byte[X25519DiffieHellman.PrivateKeySizeInBytes];
            xdh.ExportPrivateKey(privateKeySpan);
            AssertExtensions.SequenceEqual(privateKey.AsSpan(), privateKeySpan);

            using X25519DiffieHellman imported = ImportPrivateKey(privateKey);
            AssertExtensions.SequenceEqual(privateKey, imported.ExportPrivateKey());
        }

        [Fact]
        public void ExportPublicKey_Roundtrip()
        {
            using X25519DiffieHellman xdh = GenerateKey();

            byte[] publicKey = xdh.ExportPublicKey();
            Assert.True(publicKey.AsSpan().ContainsAnyExcept((byte)0));
            Assert.Equal(X25519DiffieHellman.PublicKeySizeInBytes, publicKey.Length);

            Span<byte> publicKeySpan = new byte[X25519DiffieHellman.PublicKeySizeInBytes];
            xdh.ExportPublicKey(publicKeySpan);
            AssertExtensions.SequenceEqual(publicKey.AsSpan(), publicKeySpan);

            using X25519DiffieHellman imported = ImportPublicKey(publicKey);
            AssertExtensions.SequenceEqual(publicKey, imported.ExportPublicKey());
        }

        [Fact]
        public void ExportPublicKey_PublicKeyOnly()
        {
            using X25519DiffieHellman xdh = GenerateKey();
            byte[] publicKey = xdh.ExportPublicKey();

            using X25519DiffieHellman publicOnly = ImportPublicKey(publicKey);
            AssertExtensions.SequenceEqual(publicKey, publicOnly.ExportPublicKey());
        }

        [Fact]
        public void ExportPrivateKey_PublicKeyOnly_Throws()
        {
            using X25519DiffieHellman xdh = GenerateKey();
            using X25519DiffieHellman publicOnly = ImportPublicKey(xdh.ExportPublicKey());

            Assert.Throws<CryptographicException>(() => publicOnly.ExportPrivateKey());
            Assert.Throws<CryptographicException>(() => publicOnly.ExportPrivateKey(new byte[X25519DiffieHellman.PrivateKeySizeInBytes]));
        }

        [Fact]
        public void DeriveRawSecretAgreement_Symmetric()
        {
            using X25519DiffieHellman key1 = GenerateKey();
            using X25519DiffieHellman key2 = GenerateKey();

            byte[] secret1 = key1.DeriveRawSecretAgreement(key2);
            byte[] secret2 = key2.DeriveRawSecretAgreement(key1);

            AssertExtensions.SequenceEqual(secret1, secret2);
        }

        [Fact]
        public void DeriveRawSecretAgreement_ExactBuffers()
        {
            using X25519DiffieHellman key1 = GenerateKey();
            using X25519DiffieHellman key2 = GenerateKey();

            byte[] secret1 = new byte[X25519DiffieHellman.SecretAgreementSizeInBytes];
            byte[] secret2 = new byte[X25519DiffieHellman.SecretAgreementSizeInBytes];
            key1.DeriveRawSecretAgreement(key2, secret1);
            key2.DeriveRawSecretAgreement(key1, secret2);

            AssertExtensions.SequenceEqual(secret1, secret2);
        }

        [Fact]
        public void DeriveRawSecretAgreement_PublicKeyOnly_Throws()
        {
            using X25519DiffieHellman xdh = GenerateKey();
            using X25519DiffieHellman publicOnly = ImportPublicKey(xdh.ExportPublicKey());
            using X25519DiffieHellman other = GenerateKey();

            Assert.Throws<CryptographicException>(() => publicOnly.DeriveRawSecretAgreement(other));
            Assert.Throws<CryptographicException>(() => publicOnly.DeriveRawSecretAgreement(other, new byte[X25519DiffieHellman.SecretAgreementSizeInBytes]));
        }

        [Fact]
        public void DeriveRawSecretAgreement_Rfc7748Vector()
        {
            using X25519DiffieHellman alice = ImportPrivateKey(X25519DiffieHellmanTestData.AlicePrivateKeyHex.HexToByteArray());
            using X25519DiffieHellman bob = ImportPrivateKey(X25519DiffieHellmanTestData.BobPrivateKeyHex.HexToByteArray());

            byte[] secret = alice.DeriveRawSecretAgreement(bob);
            AssertExtensions.SequenceEqual(X25519DiffieHellmanTestData.SharedSecretHex.HexToByteArray(), secret);
        }

        [Fact]
        public void DeriveRawSecretAgreement_CrossImplementation()
        {
            using X25519DiffieHellman localKey = GenerateKey();
            byte[] publicKeyBytes = localKey.ExportPublicKey();

            using X25519DiffieHellman otherParty = ImportPublicKey(publicKeyBytes);
            using X25519DiffieHellman otherFull = GenerateKey();

            byte[] secret1 = localKey.DeriveRawSecretAgreement(otherFull);
            byte[] secret2 = otherFull.DeriveRawSecretAgreement(localKey);
            AssertExtensions.SequenceEqual(secret1, secret2);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void SubjectPublicKeyInfo_Roundtrip(bool useTryExport)
        {
            using X25519DiffieHellman xdh = ImportPrivateKey(X25519DiffieHellmanTestData.AlicePrivateKeyHex.HexToByteArray());
            AssertSubjectPublicKeyInfo(xdh, useTryExport, X25519DiffieHellmanTestData.AliceSpki);
        }

        [Fact]
        public void ExportSubjectPublicKeyInfo_Allocated_Independent()
        {
            using X25519DiffieHellman xdh = GenerateKey();
            xdh.ExportSubjectPublicKeyInfo().AsSpan().Clear();
            byte[] spki1 = xdh.ExportSubjectPublicKeyInfo();
            byte[] spki2 = xdh.ExportSubjectPublicKeyInfo();
            Assert.NotSame(spki1, spki2);
            AssertExtensions.SequenceEqual(spki1, spki2);
        }

        [Fact]
        public void TryExportSubjectPublicKeyInfo_Buffers()
        {
            using X25519DiffieHellman xdh = GenerateKey();
            byte[] expectedSpki = xdh.ExportSubjectPublicKeyInfo();
            byte[] buffer;
            int written;

            buffer = new byte[expectedSpki.Length - 1];
            Assert.False(xdh.TryExportSubjectPublicKeyInfo(buffer, out written));
            Assert.Equal(0, written);

            buffer = new byte[expectedSpki.Length];
            Assert.True(xdh.TryExportSubjectPublicKeyInfo(buffer, out written));
            Assert.Equal(expectedSpki.Length, written);
            AssertExtensions.SequenceEqual(expectedSpki, buffer);

            buffer = new byte[expectedSpki.Length + 42];
            Assert.True(xdh.TryExportSubjectPublicKeyInfo(buffer, out written));
            Assert.Equal(expectedSpki.Length, written);
            AssertExtensions.SequenceEqual(expectedSpki.AsSpan(), buffer.AsSpan(0, written));
        }

        [Fact]
        public void ExportPkcs8PrivateKey_Roundtrip()
        {
            using X25519DiffieHellman xdh = ImportPrivateKey(X25519DiffieHellmanTestData.AlicePrivateKeyHex.HexToByteArray());

            AssertExportPkcs8PrivateKey(xdh, pkcs8 =>
            {
                using X25519DiffieHellman imported = X25519DiffieHellman.ImportPkcs8PrivateKey(pkcs8);
                AssertExtensions.SequenceEqual(
                    X25519DiffieHellmanTestData.AlicePrivateKeyHex.HexToByteArray(),
                    imported.ExportPrivateKey());
            });
        }

        [Fact]
        public void ExportPkcs8PrivateKey_PublicKeyOnly_Fails()
        {
            using X25519DiffieHellman xdh = ImportPublicKey(X25519DiffieHellmanTestData.AlicePublicKeyHex.HexToByteArray());
            Assert.Throws<CryptographicException>(() => DoTryUntilDone(xdh.TryExportPkcs8PrivateKey));
            Assert.Throws<CryptographicException>(() => xdh.ExportPkcs8PrivateKey());
        }

        [Fact]
        public void ExportEncryptedPkcs8PrivateKey_Roundtrip()
        {
            using X25519DiffieHellman xdh = ImportPrivateKey(X25519DiffieHellmanTestData.AlicePrivateKeyHex.HexToByteArray());
            AssertEncryptedExportPkcs8PrivateKey(
                xdh,
                X25519DiffieHellmanTestData.EncryptedPrivateKeyPassword,
                s_aes128Pbe,
                pkcs8 =>
                {
                    using X25519DiffieHellman imported = X25519DiffieHellman.ImportEncryptedPkcs8PrivateKey(
                        X25519DiffieHellmanTestData.EncryptedPrivateKeyPassword,
                        pkcs8);

                    AssertExtensions.SequenceEqual(
                        X25519DiffieHellmanTestData.AlicePrivateKeyHex.HexToByteArray(),
                        imported.ExportPrivateKey());
                });
        }

        [Fact]
        public void ExportEncryptedPkcs8PrivateKey_PublicKeyOnly_Fails()
        {
            using X25519DiffieHellman xdh = ImportPublicKey(X25519DiffieHellmanTestData.AlicePublicKeyHex.HexToByteArray());

            Assert.Throws<CryptographicException>(() => DoTryUntilDone((Span<byte> destination, out int bytesWritten) =>
                xdh.TryExportEncryptedPkcs8PrivateKey(
                    X25519DiffieHellmanTestData.EncryptedPrivateKeyPassword.AsSpan(),
                    s_aes128Pbe,
                    destination,
                    out bytesWritten)));

            Assert.Throws<CryptographicException>(() => DoTryUntilDone((Span<byte> destination, out int bytesWritten) =>
                xdh.TryExportEncryptedPkcs8PrivateKey(
                    X25519DiffieHellmanTestData.EncryptedPrivateKeyPasswordBytes,
                    s_aes128Pbe,
                    destination,
                    out bytesWritten)));

            Assert.Throws<CryptographicException>(() => xdh.ExportEncryptedPkcs8PrivateKey(
                X25519DiffieHellmanTestData.EncryptedPrivateKeyPassword, s_aes128Pbe));

            Assert.Throws<CryptographicException>(() => xdh.ExportEncryptedPkcs8PrivateKey(
                X25519DiffieHellmanTestData.EncryptedPrivateKeyPassword.AsSpan(), s_aes128Pbe));

            Assert.Throws<CryptographicException>(() => xdh.ExportEncryptedPkcs8PrivateKey(
                X25519DiffieHellmanTestData.EncryptedPrivateKeyPasswordBytes, s_aes128Pbe));

            Assert.Throws<CryptographicException>(() => xdh.ExportEncryptedPkcs8PrivateKeyPem(
                X25519DiffieHellmanTestData.EncryptedPrivateKeyPasswordBytes, s_aes128Pbe));

            Assert.Throws<CryptographicException>(() => xdh.ExportEncryptedPkcs8PrivateKeyPem(
                X25519DiffieHellmanTestData.EncryptedPrivateKeyPassword, s_aes128Pbe));

            Assert.Throws<CryptographicException>(() => xdh.ExportEncryptedPkcs8PrivateKeyPem(
                X25519DiffieHellmanTestData.EncryptedPrivateKeyPassword.AsSpan(), s_aes128Pbe));
        }

        [Theory]
        [MemberData(nameof(ExportPkcs8Parameters))]
        public void ExportEncryptedPkcs8PrivateKey_PbeParameters(PbeParameters pbeParameters)
        {
            using X25519DiffieHellman xdh = ImportPrivateKey(X25519DiffieHellmanTestData.AlicePrivateKeyHex.HexToByteArray());
            AssertEncryptedExportPkcs8PrivateKey(
                xdh,
                X25519DiffieHellmanTestData.EncryptedPrivateKeyPassword,
                pbeParameters,
                pkcs8 =>
                {
                    Pkcs8TestHelpers.AssertEncryptedPkcs8PrivateKeyContents(pbeParameters, pkcs8);
                });
        }

        public static IEnumerable<object[]> ExportPkcs8Parameters
        {
            get
            {
                yield return [new PbeParameters(PbeEncryptionAlgorithm.Aes128Cbc, HashAlgorithmName.SHA256, 42)];
                yield return [new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA512, 43)];
                yield return [new PbeParameters(PbeEncryptionAlgorithm.Aes192Cbc, HashAlgorithmName.SHA384, 44)];
                yield return [new PbeParameters(PbeEncryptionAlgorithm.TripleDes3KeyPkcs12, HashAlgorithmName.SHA1, 24)];
            }
        }

        [Fact]
        public void PrivateKey_Roundtrip_UnclampedScalar()
        {
            byte[] privateKey = X25519DiffieHellmanTestData.BobPrivateKeyHex.HexToByteArray();
            using X25519DiffieHellman xdh = ImportPrivateKey(privateKey);

            AssertExtensions.SequenceEqual(privateKey, xdh.ExportPrivateKey());
            AssertExtensions.SequenceEqual(X25519DiffieHellmanTestData.BobPublicKeyHex.HexToByteArray(), xdh.ExportPublicKey());

            byte[] pkcs8 = xdh.ExportPkcs8PrivateKey();
            using X25519DiffieHellman reimported = X25519DiffieHellman.ImportPkcs8PrivateKey(pkcs8);
            AssertExtensions.SequenceEqual(privateKey, reimported.ExportPrivateKey());
        }

        [Fact]
        public void PrivateKey_Roundtrip_ClampedScalar()
        {
            byte[] privateKey = X25519DiffieHellmanTestData.AlicePrivateKeyHex.HexToByteArray();
            privateKey[0] &= 0b11111000;
            privateKey[^1] &= 0b01111111;
            privateKey[^1] |= 0b01000000;

            using X25519DiffieHellman xdh = ImportPrivateKey(privateKey);
            AssertExtensions.SequenceEqual(privateKey, xdh.ExportPrivateKey());
        }

        [Fact]
        public void PrivateKey_ClampedAndUnclamped_SamePublicKey()
        {
            byte[] unclamped = X25519DiffieHellmanTestData.AlicePrivateKeyHex.HexToByteArray();
            byte[] clamped = (byte[])unclamped.Clone();
            clamped[0] &= 0b11111000;
            clamped[^1] &= 0b01111111;
            clamped[^1] |= 0b01000000;

            using X25519DiffieHellman xdhUnclamped = ImportPrivateKey(unclamped);
            using X25519DiffieHellman xdhClamped = ImportPrivateKey(clamped);

            AssertExtensions.SequenceEqual(xdhUnclamped.ExportPublicKey(), xdhClamped.ExportPublicKey());
        }

        private static void AssertSubjectPublicKeyInfo(X25519DiffieHellman xdh, bool useTryExport, ReadOnlySpan<byte> expectedSpki)
        {
            byte[] spki;
            int written;

            if (useTryExport)
            {
                spki = new byte[X25519DiffieHellman.PublicKeySizeInBytes + 16];
                Assert.True(xdh.TryExportSubjectPublicKeyInfo(spki, out written));
            }
            else
            {
                spki = xdh.ExportSubjectPublicKeyInfo();
                written = spki.Length;
            }

            ReadOnlySpan<byte> encodedSpki = spki.AsSpan(0, written);
            AssertExtensions.SequenceEqual(expectedSpki, encodedSpki);

            using X25519DiffieHellman imported = X25519DiffieHellman.ImportSubjectPublicKeyInfo(encodedSpki);
            AssertExtensions.SequenceEqual(xdh.ExportPublicKey(), imported.ExportPublicKey());
        }

        private static void AssertExportPkcs8PrivateKey(X25519DiffieHellman xdh, Action<byte[]> callback)
        {
            callback(DoTryUntilDone(xdh.TryExportPkcs8PrivateKey));
            callback(xdh.ExportPkcs8PrivateKey());
        }

        private static void AssertEncryptedExportPkcs8PrivateKey(
            X25519DiffieHellman xdh,
            string password,
            PbeParameters pbeParameters,
            Action<byte[]> callback)
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            callback(DoTryUntilDone((Span<byte> destination, out int bytesWritten) =>
            {
                return xdh.TryExportEncryptedPkcs8PrivateKey(
                    password.AsSpan(),
                    pbeParameters,
                    destination,
                    out bytesWritten);
            }));

            callback(xdh.ExportEncryptedPkcs8PrivateKey(password, pbeParameters));
            callback(xdh.ExportEncryptedPkcs8PrivateKey(password.AsSpan(), pbeParameters));
            callback(DecodePem(xdh.ExportEncryptedPkcs8PrivateKeyPem(password, pbeParameters)));
            callback(DecodePem(xdh.ExportEncryptedPkcs8PrivateKeyPem(password.AsSpan(), pbeParameters)));

            if (pbeParameters.EncryptionAlgorithm != PbeEncryptionAlgorithm.TripleDes3KeyPkcs12)
            {
                callback(DoTryUntilDone((Span<byte> destination, out int bytesWritten) =>
                {
                    return xdh.TryExportEncryptedPkcs8PrivateKey(
                        new ReadOnlySpan<byte>(passwordBytes),
                        pbeParameters,
                        destination,
                        out bytesWritten);
                }));

                callback(xdh.ExportEncryptedPkcs8PrivateKey(new ReadOnlySpan<byte>(passwordBytes), pbeParameters));
                callback(DecodePem(xdh.ExportEncryptedPkcs8PrivateKeyPem(new ReadOnlySpan<byte>(passwordBytes), pbeParameters)));
            }

            static byte[] DecodePem(string pem)
            {
                PemFields fields = PemEncoding.Find(pem.AsSpan());
                Assert.Equal(Index.FromStart(0), fields.Location.Start);
                Assert.Equal(Index.FromStart(pem.Length), fields.Location.End);
                Assert.Equal("ENCRYPTED PRIVATE KEY", pem.AsSpan()[fields.Label].ToString());
                return Convert.FromBase64String(pem.AsSpan()[fields.Base64Data].ToString());
            }
        }

        private delegate bool TryExportFunc(Span<byte> destination, out int bytesWritten);

        private static byte[] DoTryUntilDone(TryExportFunc func)
        {
            byte[] buffer = new byte[512];
            int written;

            while (!func(buffer, out written))
            {
                Array.Resize(ref buffer, buffer.Length * 2);
            }

            return buffer.AsSpan(0, written).ToArray();
        }
    }
}
