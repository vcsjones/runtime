// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.Generic;
using System.IO;
using System.Text;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.Encryption.Aes.Tests
{
    using Aes = System.Security.Cryptography.Aes;

    public partial class AesCipherTests
    {
        [Fact]
        public static void DecryptKnownECB192_OneShot()
        {
            byte[] encryptedBytes = new byte[]
            {
                0xC9, 0x7F, 0xA5, 0x5B, 0xC3, 0x92, 0xDC, 0xA6,
                0xE4, 0x9F, 0x2D, 0x1A, 0xEF, 0x7A, 0x27, 0x03,
                0x04, 0x9C, 0xFB, 0x56, 0x63, 0x38, 0xAE, 0x4F,
                0xDC, 0xF6, 0x36, 0x98, 0x28, 0x05, 0x32, 0xE9,
                0xF2, 0x6E, 0xEC, 0x0C, 0x04, 0x9D, 0x12, 0x17,
                0x18, 0x35, 0xD4, 0x29, 0xFC, 0x01, 0xB1, 0x20,
                0xFA, 0x30, 0xAE, 0x00, 0x53, 0xD4, 0x26, 0x25,
                0xA4, 0xFD, 0xD5, 0xE6, 0xED, 0x79, 0x35, 0x2A,
                0xE2, 0xBB, 0x95, 0x0D, 0xEF, 0x09, 0xBB, 0x6D,
                0xC5, 0xC4, 0xDB, 0x28, 0xC6, 0xF4, 0x31, 0x33,
                0x9A, 0x90, 0x12, 0x36, 0x50, 0xA0, 0xB7, 0xD1,
                0x35, 0xC4, 0xCE, 0x81, 0xE5, 0x2B, 0x85, 0x6B,
            };

            TestAesEcbDecrypt(s_aes192Key, encryptedBytes, s_multiBlockBytes);
        }

        [Fact]
        public static void VerifyKnownTransform_ECB128_OneShot_NoPadding()
        {
            TestAesEcbTransformDirectKey(
                PaddingMode.None,
                key: new byte[] { 0x00, 0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08, 0x0A, 0x0B, 0x0C, 0x0D, 0x0F, 0x10, 0x11, 0x12 },
                plainBytes: new byte[] { 0x50, 0x68, 0x12, 0xA4, 0x5F, 0x08, 0xC8, 0x89, 0xB9, 0x7F, 0x59, 0x80, 0x03, 0x8B, 0x83, 0x59 },
                cipherBytes: new byte[] { 0xD8, 0xF5, 0x32, 0x53, 0x82, 0x89, 0xEF, 0x7D, 0x06, 0xB5, 0x06, 0xA4, 0xFD, 0x5B, 0xE9, 0xC9 });
        }

        [Fact]
        public static void VerifyKnownTransform_ECB256_OneShot_NoPadding()
        {
            TestAesEcbTransformDirectKey(
                PaddingMode.None,
                key: new byte[] { 0x00, 0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08, 0x0A, 0x0B, 0x0C, 0x0D, 0x0F, 0x10, 0x11, 0x12, 0x14, 0x15, 0x16, 0x17, 0x19, 0x1A, 0x1B, 0x1C, 0x1E, 0x1F, 0x20, 0x21, 0x23, 0x24, 0x25, 0x26 },
                plainBytes: new byte[] { 0x83, 0x4E, 0xAD, 0xFC, 0xCA, 0xC7, 0xE1, 0xB3, 0x06, 0x64, 0xB1, 0xAB, 0xA4, 0x48, 0x15, 0xAB },
                cipherBytes: new byte[] { 0x19, 0x46, 0xDA, 0xBF, 0x6A, 0x03, 0xA2, 0xA2, 0xC3, 0xD0, 0xB0, 0x50, 0x80, 0xAE, 0xD6, 0xFC });
        }

        [Fact]
        public static void VerifyKnownTransform_ECB128_OneShot_NoPadding_2()
        {
            TestAesEcbTransformDirectKey(
                PaddingMode.None,
                key: new byte[] { 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                plainBytes: new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                cipherBytes: new byte[] { 0x0E, 0xDD, 0x33, 0xD3, 0xC6, 0x21, 0xE5, 0x46, 0x45, 0x5B, 0xD8, 0xBA, 0x14, 0x18, 0xBE, 0xC8 });
        }

        [Fact]
        public static void VerifyKnownTransform_ECB128_OneShot_NoPadding_3()
        {
            TestAesEcbTransformDirectKey(
                PaddingMode.None,
                key: new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                plainBytes: new byte[] { 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                cipherBytes: new byte[] { 0x3A, 0xD7, 0x8E, 0x72, 0x6C, 0x1E, 0xC0, 0x2B, 0x7E, 0xBF, 0xE9, 0x2B, 0x23, 0xD9, 0xEC, 0x34 });
        }

        [Fact]
        public static void VerifyKnownTransform_ECB192_OneShot_NoPadding()
        {
            TestAesEcbTransformDirectKey(
                PaddingMode.None,
                key: new byte[] { 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                plainBytes: new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                cipherBytes: new byte[] { 0xDE, 0x88, 0x5D, 0xC8, 0x7F, 0x5A, 0x92, 0x59, 0x40, 0x82, 0xD0, 0x2C, 0xC1, 0xE1, 0xB4, 0x2C });
        }

        [Fact]
        public static void VerifyKnownTransform_ECB192_OneShot_NoPadding_2()
        {
            TestAesEcbTransformDirectKey(
                PaddingMode.None,
                key: new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                plainBytes: new byte[] { 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                cipherBytes: new byte[] { 0x6C, 0xD0, 0x25, 0x13, 0xE8, 0xD4, 0xDC, 0x98, 0x6B, 0x4A, 0xFE, 0x08, 0x7A, 0x60, 0xBD, 0x0C });
        }

        private static void TestAesEcbDecrypt(
            byte[] key,
            byte[] encryptedBytes,
            byte[] expectedAnswer)
        {
            using Aes aes = AesFactory.Create();
            aes.Mode = CipherMode.ECB;
            aes.Key = key;

            byte[] decryptedBytes = aes.DecryptEcb(encryptedBytes, PaddingMode.PKCS7);

            Assert.NotEqual(encryptedBytes, decryptedBytes);
            Assert.Equal(expectedAnswer, decryptedBytes);
        }

        private static void TestAesEcbTransformDirectKey(
            PaddingMode paddingMode,
            byte[] key,
            byte[] plainBytes,
            byte[] cipherBytes)
        {
            using Aes aes = AesFactory.Create();
            aes.Mode = CipherMode.ECB;
            aes.Padding = paddingMode;
            aes.Key = key;

            byte[] liveEncryptBytes = aes.EncryptEcb(plainBytes, paddingMode);
            Assert.Equal(cipherBytes, liveEncryptBytes);

            byte[] liveDecryptBytes = aes.DecryptEcb(cipherBytes, paddingMode);
            Assert.Equal(plainBytes, liveDecryptBytes);
        }
    }
}
