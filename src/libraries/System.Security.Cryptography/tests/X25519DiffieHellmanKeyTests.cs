// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Formats.Asn1;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.Tests
{
    [ConditionalClass(typeof(X25519DiffieHellman), nameof(X25519DiffieHellman.IsSupported))]
    public static class X25519DiffieHellmanKeyTests
    {
        private static readonly PbeParameters s_aes128Pbe = new(PbeEncryptionAlgorithm.Aes128Cbc, HashAlgorithmName.SHA256, 2);

        // RFC 7748 Section 6.1 test vectors
        private const string AlicePrivateKey = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
        private const string AlicePublicKey = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
        private const string BobPrivateKey = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
        private const string BobPublicKey = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
        private const string SharedSecret = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

        [Fact]
        public static void Generate_Roundtrip()
        {
            using X25519DiffieHellman xdh = X25519DiffieHellman.GenerateKey();

            byte[] publicKey = xdh.ExportPublicKey();
            AssertExtensions.GreaterThanOrEqualTo(publicKey.IndexOfAnyExcept((byte)0), 0);

            byte[] privateKey = xdh.ExportPrivateKey();
            AssertExtensions.GreaterThanOrEqualTo(privateKey.IndexOfAnyExcept((byte)0), 0);

            Assert.Equal(X25519DiffieHellman.PublicKeySizeInBytes, publicKey.Length);
            Assert.Equal(X25519DiffieHellman.PrivateKeySizeInBytes, privateKey.Length);
            AssertExtensions.SequenceNotEqual(publicKey, privateKey);

            using X25519DiffieHellman xdh2 = X25519DiffieHellman.ImportPublicKey(publicKey);
            byte[] publicKey2 = xdh2.ExportPublicKey();
            AssertExtensions.SequenceEqual(publicKey, publicKey2);

            using X25519DiffieHellman xdh3 = X25519DiffieHellman.ImportPrivateKey(privateKey);
            byte[] privateKey2 = xdh3.ExportPrivateKey();
            AssertExtensions.SequenceEqual(privateKey, privateKey2);
        }

        [Fact]
        public static void Rfc7748_TestVector_Alice()
        {
            using X25519DiffieHellman alice = X25519DiffieHellman.ImportPrivateKey(AlicePrivateKey.HexToByteArray());
            using X25519DiffieHellman bob = X25519DiffieHellman.ImportPublicKey(BobPublicKey.HexToByteArray());

            byte[] sharedSecret = alice.DeriveRawSecretAgreement(bob);
            AssertExtensions.SequenceEqual(SharedSecret.HexToByteArray(), sharedSecret);

            AssertExtensions.SequenceEqual(AlicePublicKey.HexToByteArray(), alice.ExportPublicKey());
            AssertExtensions.SequenceEqual(AlicePrivateKey.HexToByteArray(), alice.ExportPrivateKey());
        }

        [Fact]
        public static void Rfc7748_TestVector_Bob()
        {
            using X25519DiffieHellman bob = X25519DiffieHellman.ImportPrivateKey(BobPrivateKey.HexToByteArray());
            using X25519DiffieHellman alice = X25519DiffieHellman.ImportPublicKey(AlicePublicKey.HexToByteArray());

            byte[] sharedSecret = bob.DeriveRawSecretAgreement(alice);
            AssertExtensions.SequenceEqual(SharedSecret.HexToByteArray(), sharedSecret);

            AssertExtensions.SequenceEqual(BobPublicKey.HexToByteArray(), bob.ExportPublicKey());
            AssertExtensions.SequenceEqual(BobPrivateKey.HexToByteArray(), bob.ExportPrivateKey());
        }

        [Fact]
        public static void DeriveSecretAgreement_Symmetric()
        {
            using X25519DiffieHellman key1 = X25519DiffieHellman.GenerateKey();
            using X25519DiffieHellman key2 = X25519DiffieHellman.GenerateKey();

            byte[] secret1 = key1.DeriveRawSecretAgreement(key2);
            byte[] secret2 = key2.DeriveRawSecretAgreement(key1);

            AssertExtensions.SequenceEqual(secret1, secret2);
        }

        [Fact]
        public static void ImportPrivateKey_Roundtrip_Array()
        {
            byte[] privateKeyBytes = AlicePrivateKey.HexToByteArray();
            using X25519DiffieHellman xdh = X25519DiffieHellman.ImportPrivateKey(privateKeyBytes);

            byte[] exported = xdh.ExportPrivateKey();
            AssertExtensions.SequenceEqual(privateKeyBytes, exported);
        }

        [Fact]
        public static void ImportPrivateKey_Roundtrip_Span()
        {
            ReadOnlySpan<byte> privateKeyBytes = AlicePrivateKey.HexToByteArray();
            using X25519DiffieHellman xdh = X25519DiffieHellman.ImportPrivateKey(privateKeyBytes);

            Span<byte> exported = new byte[X25519DiffieHellman.PrivateKeySizeInBytes];
            xdh.ExportPrivateKey(exported);
            AssertExtensions.SequenceEqual(privateKeyBytes, exported);
        }

        [Fact]
        public static void ImportPublicKey_Roundtrip_Array()
        {
            byte[] publicKeyBytes = AlicePublicKey.HexToByteArray();
            using X25519DiffieHellman xdh = X25519DiffieHellman.ImportPublicKey(publicKeyBytes);

            byte[] exported = xdh.ExportPublicKey();
            AssertExtensions.SequenceEqual(publicKeyBytes, exported);
        }

        [Fact]
        public static void ImportPublicKey_Roundtrip_Span()
        {
            ReadOnlySpan<byte> publicKeyBytes = AlicePublicKey.HexToByteArray();
            using X25519DiffieHellman xdh = X25519DiffieHellman.ImportPublicKey(publicKeyBytes);

            Span<byte> exported = new byte[X25519DiffieHellman.PublicKeySizeInBytes];
            xdh.ExportPublicKey(exported);
            AssertExtensions.SequenceEqual(publicKeyBytes, exported);
        }

        [Fact]
        public static void ExportSubjectPublicKeyInfo_Roundtrip()
        {
            using X25519DiffieHellman xdh = X25519DiffieHellman.ImportPrivateKey(AlicePrivateKey.HexToByteArray());
            byte[] spki = xdh.ExportSubjectPublicKeyInfo();

            using X25519DiffieHellman imported = X25519DiffieHellman.ImportSubjectPublicKeyInfo(spki);
            AssertExtensions.SequenceEqual(AlicePublicKey.HexToByteArray(), imported.ExportPublicKey());
        }

        [Fact]
        public static void TryExportSubjectPublicKeyInfo_Roundtrip()
        {
            using X25519DiffieHellman xdh = X25519DiffieHellman.ImportPrivateKey(AlicePrivateKey.HexToByteArray());
            byte[] buffer = new byte[256];
            AssertExtensions.TrueExpression(xdh.TryExportSubjectPublicKeyInfo(buffer, out int written));

            using X25519DiffieHellman imported = X25519DiffieHellman.ImportSubjectPublicKeyInfo(buffer.AsSpan(0, written));
            AssertExtensions.SequenceEqual(AlicePublicKey.HexToByteArray(), imported.ExportPublicKey());
        }

        [Fact]
        public static void ImportSubjectPublicKeyInfo_KnownValue()
        {
            // SPKI for Alice's public key: SEQUENCE { SEQUENCE { OID 1.3.101.110 } BIT STRING <public key> }
            byte[] spki = Convert.FromHexString(
                "302a300506032b656e032100" +
                AlicePublicKey);

            using X25519DiffieHellman xdh = X25519DiffieHellman.ImportSubjectPublicKeyInfo(spki);
            AssertExtensions.SequenceEqual(AlicePublicKey.HexToByteArray(), xdh.ExportPublicKey());
        }

        [Fact]
        public static void ExportPkcs8PrivateKey_Roundtrip()
        {
            using X25519DiffieHellman xdh = X25519DiffieHellman.ImportPrivateKey(AlicePrivateKey.HexToByteArray());
            byte[] pkcs8 = xdh.ExportPkcs8PrivateKey();

            using X25519DiffieHellman imported = X25519DiffieHellman.ImportPkcs8PrivateKey(pkcs8);
            AssertExtensions.SequenceEqual(AlicePrivateKey.HexToByteArray(), imported.ExportPrivateKey());
            AssertExtensions.SequenceEqual(AlicePublicKey.HexToByteArray(), imported.ExportPublicKey());
        }

        [Fact]
        public static void TryExportPkcs8PrivateKey_Roundtrip()
        {
            using X25519DiffieHellman xdh = X25519DiffieHellman.ImportPrivateKey(AlicePrivateKey.HexToByteArray());
            byte[] buffer = new byte[256];
            AssertExtensions.TrueExpression(xdh.TryExportPkcs8PrivateKey(buffer, out int written));

            using X25519DiffieHellman imported = X25519DiffieHellman.ImportPkcs8PrivateKey(buffer.AsSpan(0, written));
            AssertExtensions.SequenceEqual(AlicePrivateKey.HexToByteArray(), imported.ExportPrivateKey());
        }

        [Fact]
        public static void ImportPkcs8PrivateKey_KnownValue()
        {
            // PKCS#8 for Alice's private key
            byte[] pkcs8 = Convert.FromHexString(
                "302e020100300506032b656e04220420" +
                AlicePrivateKey);

            using X25519DiffieHellman xdh = X25519DiffieHellman.ImportPkcs8PrivateKey(pkcs8);
            AssertExtensions.SequenceEqual(AlicePrivateKey.HexToByteArray(), xdh.ExportPrivateKey());
            AssertExtensions.SequenceEqual(AlicePublicKey.HexToByteArray(), xdh.ExportPublicKey());
        }

        [Fact]
        [SkipOnPlatform(TestPlatforms.Browser, "Browser does not support symmetric encryption")]
        public static void ExportEncryptedPkcs8PrivateKey_Roundtrip()
        {
            using X25519DiffieHellman xdh = X25519DiffieHellman.ImportPrivateKey(AlicePrivateKey.HexToByteArray());
            byte[] encrypted = xdh.ExportEncryptedPkcs8PrivateKey("test", s_aes128Pbe);

            using X25519DiffieHellman imported = X25519DiffieHellman.ImportEncryptedPkcs8PrivateKey("test", encrypted);
            AssertExtensions.SequenceEqual(AlicePrivateKey.HexToByteArray(), imported.ExportPrivateKey());
        }

        [Fact]
        [SkipOnPlatform(TestPlatforms.Browser, "Browser does not support symmetric encryption")]
        public static void ExportEncryptedPkcs8PrivateKey_Roundtrip_BytePassword()
        {
            using X25519DiffieHellman xdh = X25519DiffieHellman.ImportPrivateKey(AlicePrivateKey.HexToByteArray());
            byte[] encrypted = xdh.ExportEncryptedPkcs8PrivateKey("test"u8, s_aes128Pbe);

            using X25519DiffieHellman imported = X25519DiffieHellman.ImportEncryptedPkcs8PrivateKey("test"u8, encrypted);
            AssertExtensions.SequenceEqual(AlicePrivateKey.HexToByteArray(), imported.ExportPrivateKey());
        }

        [Fact]
        public static void ImportFromPem_PublicKey()
        {
            string pem =
                "-----BEGIN PUBLIC KEY-----\n" +
                "MCowBQYDK2VuAyEAhSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=\n" +
                "-----END PUBLIC KEY-----";

            using X25519DiffieHellman xdh = X25519DiffieHellman.ImportFromPem(pem);
            AssertExtensions.SequenceEqual(AlicePublicKey.HexToByteArray(), xdh.ExportPublicKey());
        }

        [Fact]
        public static void ImportFromPem_PrivateKey()
        {
            using X25519DiffieHellman xdh = X25519DiffieHellman.ImportPrivateKey(AlicePrivateKey.HexToByteArray());
            string pem = xdh.ExportPkcs8PrivateKeyPem();

            using X25519DiffieHellman imported = X25519DiffieHellman.ImportFromPem(pem);
            AssertExtensions.SequenceEqual(AlicePrivateKey.HexToByteArray(), imported.ExportPrivateKey());
        }

        [Fact]
        [SkipOnPlatform(TestPlatforms.Browser, "Browser does not support symmetric encryption")]
        public static void ImportFromEncryptedPem_Roundtrip()
        {
            using X25519DiffieHellman xdh = X25519DiffieHellman.ImportPrivateKey(AlicePrivateKey.HexToByteArray());
            string pem = xdh.ExportEncryptedPkcs8PrivateKeyPem("test", s_aes128Pbe);

            using X25519DiffieHellman imported = X25519DiffieHellman.ImportFromEncryptedPem(pem, "test");
            AssertExtensions.SequenceEqual(AlicePrivateKey.HexToByteArray(), imported.ExportPrivateKey());
        }

        [Fact]
        public static void ExportSubjectPublicKeyInfoPem_Roundtrip()
        {
            using X25519DiffieHellman xdh = X25519DiffieHellman.ImportPrivateKey(AlicePrivateKey.HexToByteArray());
            string pem = xdh.ExportSubjectPublicKeyInfoPem();

            PemFields fields = PemEncoding.Find(pem.AsSpan());
            Assert.Equal("PUBLIC KEY", pem.AsSpan()[fields.Label].ToString());

            using X25519DiffieHellman imported = X25519DiffieHellman.ImportFromPem(pem);
            AssertExtensions.SequenceEqual(AlicePublicKey.HexToByteArray(), imported.ExportPublicKey());
        }

        [Fact]
        public static void ExportPkcs8PrivateKeyPem_Roundtrip()
        {
            using X25519DiffieHellman xdh = X25519DiffieHellman.ImportPrivateKey(AlicePrivateKey.HexToByteArray());
            string pem = xdh.ExportPkcs8PrivateKeyPem();

            PemFields fields = PemEncoding.Find(pem.AsSpan());
            Assert.Equal("PRIVATE KEY", pem.AsSpan()[fields.Label].ToString());

            using X25519DiffieHellman imported = X25519DiffieHellman.ImportFromPem(pem);
            AssertExtensions.SequenceEqual(AlicePrivateKey.HexToByteArray(), imported.ExportPrivateKey());
        }

        [Fact]
        public static void DeriveSecretAgreement_PublicKeyOnly_Throws()
        {
            using X25519DiffieHellman publicOnly = X25519DiffieHellman.ImportPublicKey(AlicePublicKey.HexToByteArray());
            using X25519DiffieHellman other = X25519DiffieHellman.ImportPublicKey(BobPublicKey.HexToByteArray());

            Assert.Throws<CryptographicException>(() => publicOnly.DeriveRawSecretAgreement(other));
        }

        [Fact]
        public static void ExportPrivateKey_PublicKeyOnly_Throws()
        {
            using X25519DiffieHellman publicOnly = X25519DiffieHellman.ImportPublicKey(AlicePublicKey.HexToByteArray());

            Assert.Throws<CryptographicException>(() => publicOnly.ExportPrivateKey());
        }
    }
}
