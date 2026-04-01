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
    }
}