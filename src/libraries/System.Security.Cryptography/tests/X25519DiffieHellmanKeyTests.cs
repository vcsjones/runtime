// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Xunit;

namespace System.Security.Cryptography.Tests
{
    [ConditionalClass(typeof(X25519DiffieHellman), nameof(X25519DiffieHellman.IsSupported))]
    public static class X25519DiffieHellmanKeyTests
    {
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
        public static void TestVector1()
        {
            using X25519DiffieHellman alice = X25519DiffieHellman.ImportPrivateKey(
                Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
            using X25519DiffieHellman bob = X25519DiffieHellman.ImportPublicKey(
                Convert.FromHexString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));

            byte[] expectedSharedSecret = Convert.FromHexString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

            byte[] sharedSecret = alice.DeriveRawSecretAgreement(bob);
            AssertExtensions.SequenceEqual(expectedSharedSecret, sharedSecret);
        }

        [Fact]
        public static void TestVector2()
        {
            using X25519DiffieHellman alice = X25519DiffieHellman.ImportPublicKey(
                Convert.FromHexString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
            using X25519DiffieHellman bob = X25519DiffieHellman.ImportPrivateKey(
                Convert.FromHexString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));

            byte[] expectedSharedSecret = Convert.FromHexString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

            byte[] sharedSecret = bob.DeriveRawSecretAgreement(alice);
            AssertExtensions.SequenceEqual(expectedSharedSecret, sharedSecret);
        }
    }
}