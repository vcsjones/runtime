// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Xunit;

namespace System.Security.Cryptography.Tests
{
    [ConditionalClass(typeof(Ed25519), nameof(Ed25519.IsSupported))]
    public static class Ed25519KeyTests
    {
        [Fact]
        public static void Generate_Roundtrip()
        {
            using Ed25519 key = Ed25519.GenerateKey();

            byte[] publicKey = key.ExportPublicKey();
            AssertExtensions.GreaterThanOrEqualTo(publicKey.IndexOfAnyExcept((byte)0), 0);

            byte[] privateKey = key.ExportPrivateKey();
            AssertExtensions.GreaterThanOrEqualTo(privateKey.IndexOfAnyExcept((byte)0), 0);

            Assert.Equal(Ed25519.PublicKeySizeInBytes, publicKey.Length);
            Assert.Equal(Ed25519.PrivateKeySizeInBytes, privateKey.Length);
            AssertExtensions.SequenceNotEqual(publicKey, privateKey);

            using Ed25519 publicKeyOnly = Ed25519.ImportPublicKey(publicKey);
            AssertExtensions.SequenceEqual(publicKey, publicKeyOnly.ExportPublicKey());
            Assert.Throws<CryptographicException>(() => publicKeyOnly.ExportPrivateKey());

            using Ed25519 privateKeyOnly = Ed25519.ImportPrivateKey(privateKey);
            AssertExtensions.SequenceEqual(privateKey, privateKeyOnly.ExportPrivateKey());
        }

        [Fact]
        public static void SignVerify_Roundtrip()
        {
            byte[] data = [1, 2, 3, 4, 5];

            using Ed25519 key = Ed25519.GenerateKey();
            byte[] signature = key.SignData(data);

            Assert.Equal(Ed25519.SignatureSizeInBytes, signature.Length);
            Assert.True(key.VerifyData(data, signature));
            Assert.False(key.VerifyData(new byte[] { 1, 2, 3, 4, 6 }, signature));
            Assert.False(key.VerifyData(data, signature.AsSpan(0, signature.Length - 1)));

            byte[] publicKey = key.ExportPublicKey();

            using Ed25519 publicKeyOnly = Ed25519.ImportPublicKey(publicKey);
            Assert.True(publicKeyOnly.VerifyData(data, signature));
            Assert.Throws<CryptographicException>(() => publicKeyOnly.SignData(data));

            Span<byte> destination = stackalloc byte[Ed25519.SignatureSizeInBytes];
            key.SignData(data, destination);
            Assert.True(key.VerifyData(data, destination));
        }
    }
}
