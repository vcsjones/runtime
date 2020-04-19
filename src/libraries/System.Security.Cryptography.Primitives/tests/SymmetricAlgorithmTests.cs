// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using Xunit;

namespace System.Security.Cryptography.Primitives.Tests
{
    public static class SymmetricAlgorithmTests
    {
        [Theory]
        [MemberData(nameof(CiphertextLengthTheories))]
        public static void GetCiphertextLength_TypicalBlockSize(PaddingMode mode, int plaintextSize, int expectedCiphertextSize)
        {
            AnyBlockSizeAlgorithm alg = new AnyBlockSizeAlgorithm { BlockSize = 128 };
            int ciphertextSize = alg.GetCiphertextLength(mode, plaintextSize);
            Assert.Equal(expectedCiphertextSize, ciphertextSize);
        }

        [Theory]
        [InlineData(PaddingMode.ANSIX923)]
        [InlineData(PaddingMode.ISO10126)]
        [InlineData(PaddingMode.PKCS7)]
        [InlineData(PaddingMode.Zeros)]
        public static void GetCiphertextLength_NonTypicalBlockSize(PaddingMode mode)
        {
            AnyBlockSizeAlgorithm alg = new AnyBlockSizeAlgorithm { BlockSize = 22 * 8 };
            int ciphertextSize = alg.GetCiphertextLength(mode, 22 * 8 + 1);
            Assert.Equal(22 * 9, ciphertextSize);
        }

        [Theory]
        [InlineData(PaddingMode.ANSIX923)]
        [InlineData(PaddingMode.ISO10126)]
        [InlineData(PaddingMode.PKCS7)]
        public static void GetCiphertextLength_BlockSizeIsOne(PaddingMode mode)
        {
            AnyBlockSizeAlgorithm alg = new AnyBlockSizeAlgorithm { BlockSize = 8 };
            int ciphertextSize = alg.GetCiphertextLength(mode, 8);
            Assert.Equal(9, ciphertextSize);
        }

        [Theory]
        [InlineData(PaddingMode.ANSIX923)]
        [InlineData(PaddingMode.ISO10126)]
        [InlineData(PaddingMode.None)]
        [InlineData(PaddingMode.PKCS7)]
        [InlineData(PaddingMode.Zeros)]
        public static void GetCiphertextLength_ThrowsForNegativeInput(PaddingMode mode)
        {
            AnyBlockSizeAlgorithm alg = new AnyBlockSizeAlgorithm { BlockSize = 128 };
            AssertExtensions.Throws<ArgumentOutOfRangeException>("plaintextLength", () => alg.GetCiphertextLength(mode, -1));
        }

        [Theory]
        [InlineData(PaddingMode.ANSIX923)]
        [InlineData(PaddingMode.ISO10126)]
        [InlineData(PaddingMode.PKCS7)]
        [InlineData(PaddingMode.Zeros)]
        public static void GetCiphertextLength_ThrowsForOverflow(PaddingMode mode)
        {
            AnyBlockSizeAlgorithm alg = new AnyBlockSizeAlgorithm { BlockSize = 128 };
            AssertExtensions.Throws<ArgumentOutOfRangeException>("plaintextLength", () => alg.GetCiphertextLength(mode, 0x7FFFFFF1));
        }

        [Theory]
        [InlineData(PaddingMode.ANSIX923)]
        [InlineData(PaddingMode.ISO10126)]
        [InlineData(PaddingMode.PKCS7)]
        [InlineData(PaddingMode.Zeros)]
        public static void GetCiphertextLength_ThrowsForNonByteBlockSize(PaddingMode mode)
        {
            AnyBlockSizeAlgorithm alg = new AnyBlockSizeAlgorithm { BlockSize = 5 };
            Assert.Throws<CryptographicException>(() => alg.GetCiphertextLength(mode, 16));
        }

        [Theory]
        [InlineData(PaddingMode.ANSIX923)]
        [InlineData(PaddingMode.ISO10126)]
        [InlineData(PaddingMode.PKCS7)]
        [InlineData(PaddingMode.Zeros)]
        public static void GetCiphertextLength_ThrowsForZeroBlockSize(PaddingMode mode)
        {
            AnyBlockSizeAlgorithm alg = new AnyBlockSizeAlgorithm { BlockSize = 0 };
            Assert.Throws<CryptographicException>(() => alg.GetCiphertextLength(mode, 16));
        }

        [Fact]
        public static void GetCiphertextLength_ThrowsForInvalidPaddingMode()
        {
            AnyBlockSizeAlgorithm alg = new AnyBlockSizeAlgorithm { BlockSize = 128 };
            PaddingMode mode = (PaddingMode)(-1);
            Assert.Throws<ArgumentOutOfRangeException>("paddingMode", () => alg.GetCiphertextLength(mode, 16));
        }

        [Fact]
        public static void GetCiphertextLength_NoPaddingAndPlaintextSizeNotMultiple()
        {
            AnyBlockSizeAlgorithm alg = new AnyBlockSizeAlgorithm { BlockSize = 128 };
            Assert.Throws<ArgumentException>("plaintextLength", () => alg.GetCiphertextLength(PaddingMode.None, 17));
        }

        public static IEnumerable<object[]> CiphertextLengthTheories
        {
            get
            {
                PaddingMode[] fullPaddings = new[] {
                    PaddingMode.ANSIX923,
                    PaddingMode.ISO10126,
                    PaddingMode.PKCS7,
                };

                foreach (PaddingMode mode in fullPaddings)
                {
                    yield return new object[] { mode, 00, 16 };
                    yield return new object[] { mode, 15, 16 };
                    yield return new object[] { mode, 16, 32 };
                    yield return new object[] { mode, 17, 32 };
                    yield return new object[] { mode, 1023, 1024 };
                    yield return new object[] { mode, 0x7FFFFFEF, 0x7FFFFFF0 };
                }

                PaddingMode[] noPadOnBlockSize = new[] {
                    PaddingMode.Zeros,
                    PaddingMode.None,
                };

                foreach(PaddingMode mode in noPadOnBlockSize)
                {
                    yield return new object[] { mode, 16, 16 };
                    yield return new object[] { mode, 00, 00};
                    yield return new object[] { mode, 1024, 1024};
                    yield return new object[] { mode, 0x7FFFFFF0, 0x7FFFFFF0 };
                }

                yield return new object[] { PaddingMode.Zeros, 15, 16 };
                yield return new object[] { PaddingMode.Zeros, 17, 32 };
                yield return new object[] { PaddingMode.Zeros, 0x7FFFFFEF, 0x7FFFFFF0 };
            }
        }

        private class AnyBlockSizeAlgorithm : SymmetricAlgorithm
        {
            public override int BlockSize
            {
                get => BlockSizeValue;
                set => BlockSizeValue = value;
            }

            public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV) =>
                throw new NotImplementedException();
            public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV) =>
                throw new NotImplementedException();
            public override void GenerateIV() => throw new NotImplementedException();
            public override void GenerateKey() => throw new NotImplementedException();
        }
    }
}
