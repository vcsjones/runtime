// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Xunit;

namespace System.Security.Cryptography.Tests
{
    // The abstract test class that tests instance members of Ed25519. It tests the internal
    // "Implementation" by platform, as well as any platform specific implementations that
    // derive from Ed25519.
    public abstract class Ed25519BaseTests
    {
        private static ReadOnlySpan<byte> Data => [1, 2, 3, 4, 5];
        private static ReadOnlySpan<byte> OtherData => [1, 2, 3, 4, 6];

        public abstract Ed25519 GenerateKey();
        public abstract Ed25519 ImportPrivateKey(ReadOnlySpan<byte> source);
        public abstract Ed25519 ImportPublicKey(ReadOnlySpan<byte> source);

        [Fact]
        public void SignVerify_Roundtrip()
        {
            using Ed25519 key = GenerateKey();

            byte[] signature = key.SignData(Data.ToArray());

            Assert.Equal(Ed25519.SignatureSizeInBytes, signature.Length);
            Assert.True(key.VerifyData(Data, signature));
        }

        [Fact]
        public void SignVerify_Roundtrip_ExactBuffer()
        {
            using Ed25519 key = GenerateKey();
            Span<byte> signature = stackalloc byte[Ed25519.SignatureSizeInBytes];

            key.SignData(Data, signature);

            Assert.True(key.VerifyData(Data, signature));
        }

        [Theory]
        [InlineData(Ed25519.SignatureSizeInBytes - 1)]
        [InlineData(Ed25519.SignatureSizeInBytes + 1)]
        public void SignData_DestinationWrongSize_Throws(int destinationLength)
        {
            using Ed25519 key = GenerateKey();

            AssertExtensions.Throws<ArgumentException>(
                "destination",
                () => key.SignData(Data, new byte[destinationLength]));
        }

        [Fact]
        public void SignData_PublicKeyOnly_Throws()
        {
            using Ed25519 key = GenerateKey();
            using Ed25519 publicKeyOnly = ImportPublicKey(key.ExportPublicKey());

            Assert.Throws<CryptographicException>(() => publicKeyOnly.SignData(Data.ToArray()));
            Assert.Throws<CryptographicException>(() => publicKeyOnly.SignData(Data, new byte[Ed25519.SignatureSizeInBytes]));
        }

        [Fact]
        public void VerifyData_PublicKeyOnly()
        {
            using Ed25519 key = GenerateKey();
            byte[] publicKey = key.ExportPublicKey();
            byte[] signature = key.SignData(Data.ToArray());

            using Ed25519 publicKeyOnly = ImportPublicKey(publicKey);

            Assert.True(publicKeyOnly.VerifyData(Data, signature));
            Assert.True(publicKeyOnly.VerifyData(Data.ToArray(), signature));
        }

        [Fact]
        public void VerifyData_WrongData_ReturnsFalse()
        {
            using Ed25519 key = GenerateKey();
            byte[] signature = key.SignData(Data.ToArray());

            Assert.False(key.VerifyData(OtherData, signature));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(Ed25519.SignatureSizeInBytes - 1)]
        [InlineData(Ed25519.SignatureSizeInBytes + 1)]
        public void VerifyData_WrongSignatureSize_ReturnsFalse(int signatureLength)
        {
            using Ed25519 key = GenerateKey();

            Assert.False(key.VerifyData(Data, new byte[signatureLength]));
        }

        [Fact]
        public void VerifyData_TamperedSignature_ReturnsFalse()
        {
            using Ed25519 key = GenerateKey();
            byte[] signature = key.SignData(Data.ToArray());
            signature[0] ^= 0xFF;

            Assert.False(key.VerifyData(Data, signature));
        }

        [Fact]
        public void SignData_ImportedPrivateKey_Roundtrip()
        {
            using Ed25519 key = GenerateKey();
            byte[] privateKey = key.ExportPrivateKey();

            using Ed25519 imported = ImportPrivateKey(privateKey);
            byte[] signature = imported.SignData(Data.ToArray());

            Assert.True(key.VerifyData(Data, signature));
        }
    }
}
