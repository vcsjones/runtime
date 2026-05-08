// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.Dsa.Tests
{
    [ConditionalClass(typeof(PlatformSupport), nameof(PlatformSupport.IsDSASupported))]
    public partial class DSAKeyGeneration
    {
        public static bool HasSecondMinSize { get; } = GetHasSecondMinSize();

        [Fact]
        public static void VerifyDefaultKeySize_Fips186_2()
        {
            if (!DSAFactory.SupportsFips186_3)
            {
                using (DSA dsa = DSAFactory.Create())
                {
                    Assert.True(dsa.KeySize <= 1024); // KeySize must be <= 1024 for FIPS 186-2
                }
            }
        }

        [Fact]
        public static void GenerateMinKey()
        {
            GenerateKey(dsa => GetMin(dsa.LegalKeySizes));
        }

        [ConditionalFact(typeof(DSAKeyGeneration), nameof(HasSecondMinSize))]
        public static void GenerateSecondMinKey()
        {
            GenerateKey(dsa => GetSecondMin(dsa.LegalKeySizes));
        }

        [Fact]
        public static void GenerateKey_1024()
        {
            GenerateKey(1024);
        }

        [ConditionalTheory(typeof(PlatformDetection), nameof(PlatformDetection.IsAndroid))]
        [InlineData(0)]
        [InlineData(2048)]
        public static void GenerateKey_Android2048_CanSignWithSha1(int keySize)
        {
            using DSA dsa = keySize == 0 ? DSAFactory.Create() : DSAFactory.Create(keySize);

            DSAParameters parameters = dsa.ExportParameters(false);
            int pBits = parameters.P!.Length * 8;
            int qBits = parameters.Q!.Length * 8;
            Assert.True(
                IsValidGeneratedParameterSize(pBits, qBits),
                $"Expected valid DSA parameter sizes, got L={pBits}, N={qBits}.");

            byte[] hash;
            using (SHA1 sha = SHA1.Create())
            {
                hash = sha.ComputeHash(DSATestData.HelloBytes);
            }

            byte[] signature = dsa.CreateSignature(hash);
            Assert.True(dsa.VerifySignature(hash, signature));
        }

        private static void GenerateKey(int size)
        {
            GenerateKey(dsa => size);
        }

        private static void GenerateKey(Func<DSA, int> getSize)
        {
            int keySize;

            using (DSA dsa = DSAFactory.Create())
            {
                keySize = getSize(dsa);
            }

            using (DSA dsa = DSAFactory.Create(keySize))
            {
                Assert.Equal(keySize, dsa.KeySize);

                // Some providers may generate the key in the constructor, but
                // all of them should have generated it before answering ExportParameters.
                DSAParameters keyParameters = dsa.ExportParameters(false);
                DSAImportExport.ValidateParameters(ref keyParameters);

                // KeySize should still be what we set it to originally.
                Assert.Equal(keySize, dsa.KeySize);

                dsa.ImportParameters(keyParameters);
                Assert.Equal(keySize, dsa.KeySize);
            }
        }

        private static int GetMin(KeySizes[] keySizes)
        {
            int min = int.MaxValue;

            foreach (var keySize in keySizes)
            {
                if (keySize.MinSize < min)
                {
                    min = keySize.MinSize;
                }
            }

            return min;
        }

        private static bool IsValidGeneratedParameterSize(int pBits, int qBits) =>
            (pBits, qBits) is (1024, 160) or (2048, 224) or (2048, 256) or (3072, 256);

        private static int GetSecondMin(KeySizes[] keySizes)
        {
            int secondMin = int.MaxValue;
            int min = secondMin;

            foreach (var keySize in keySizes)
            {
                int localMin = keySize.MinSize;

                if (localMin < min)
                {
                    secondMin = min;
                    min = localMin;
                }
                else if (localMin < secondMin)
                {
                    secondMin = localMin;
                }

                if (keySize.MaxSize != keySize.MinSize)
                {
                    int secondLocal = localMin + keySize.SkipSize;

                    if (secondLocal < secondMin)
                    {
                        secondMin = secondLocal;
                    }
                }
            }

            return secondMin;
        }

        private static bool GetHasSecondMinSize()
        {
            try
            {
                using (DSA dsa = DSAFactory.Create())
                {
                    return GetSecondMin(dsa.LegalKeySizes) != int.MaxValue;
                }
            }
            catch (PlatformNotSupportedException)
            {
                return false;
            }
        }
    }
}
