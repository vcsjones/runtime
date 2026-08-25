// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Security.Cryptography.Pkcs.Tests;
using System.Security.Cryptography.Tests;
using System.Security.Cryptography.X509Certificates;
using Xunit;

using Test.Cryptography;

namespace System.Security.Cryptography.Pkcs.EnvelopedCmsTests.Tests
{
    public static partial class GeneralTests
    {
        public static IEnumerable<object[]> MLKemDocuments =>
        [
            [
                MLKemTestDocuments.MLKem512WithoutUserKeyingMaterial,
                MLKemTestData.IetfMlKem512PrivateKeySeedPem,
                MLKemTestDocuments.MLKem512Content,
                null,
            ],
            [
                MLKemTestDocuments.MLKem512WithUserKeyingMaterial,
                MLKemTestData.IetfMlKem512PrivateKeySeedPem,
                MLKemTestDocuments.MLKem512Content,
                MLKemTestDocuments.MLKem512UserKeyingMaterial,
            ],
            [
                MLKemTestDocuments.MLKem768WithoutUserKeyingMaterial,
                MLKemTestData.IetfMlKem768PrivateKeySeedPem,
                MLKemTestDocuments.MLKem768Content,
                null,
            ],
            [
                MLKemTestDocuments.MLKem768WithUserKeyingMaterial,
                MLKemTestData.IetfMlKem768PrivateKeySeedPem,
                MLKemTestDocuments.MLKem768Content,
                MLKemTestDocuments.MLKem768UserKeyingMaterial,
            ],
            [
                MLKemTestDocuments.MLKem768WithEmptyUserKeyingMaterial,
                MLKemTestData.IetfMlKem768PrivateKeySeedPem,
                MLKemTestDocuments.MLKem768Content,
                Array.Empty<byte>(),
            ],
            [
                MLKemTestDocuments.MLKem1024WithoutUserKeyingMaterial,
                MLKemTestData.IetfMlKem1024PrivateKeySeedPem,
                MLKemTestDocuments.MLKem1024Content,
                null,
            ],
            [
                MLKemTestDocuments.MLKem1024WithUserKeyingMaterial,
                MLKemTestData.IetfMlKem1024PrivateKeySeedPem,
                MLKemTestDocuments.MLKem1024Content,
                MLKemTestDocuments.MLKem1024UserKeyingMaterial,
            ],
        ];

        public static IEnumerable<object[]> MLKemCertificateDocuments =>
        [
            [
                MLKemTestDocuments.MLKem512WithoutUserKeyingMaterial,
                MLKemTestData.IetfMlKem512PrivateKeySeedPfx,
                MLKemTestDocuments.MLKem512Content,
                null,
            ],
            [
                MLKemTestDocuments.MLKem512WithUserKeyingMaterial,
                MLKemTestData.IetfMlKem512PrivateKeySeedPfx,
                MLKemTestDocuments.MLKem512Content,
                MLKemTestDocuments.MLKem512UserKeyingMaterial,
            ],
            [
                MLKemTestDocuments.MLKem768WithoutUserKeyingMaterial,
                MLKemTestData.IetfMlKem768PrivateKeySeedPfx,
                MLKemTestDocuments.MLKem768Content,
                null,
            ],
            [
                MLKemTestDocuments.MLKem768WithUserKeyingMaterial,
                MLKemTestData.IetfMlKem768PrivateKeySeedPfx,
                MLKemTestDocuments.MLKem768Content,
                MLKemTestDocuments.MLKem768UserKeyingMaterial,
            ],
            [
                MLKemTestDocuments.MLKem768WithEmptyUserKeyingMaterial,
                MLKemTestData.IetfMlKem768PrivateKeySeedPfx,
                MLKemTestDocuments.MLKem768Content,
                Array.Empty<byte>(),
            ],
            [
                MLKemTestDocuments.MLKem1024WithoutUserKeyingMaterial,
                MLKemTestData.IetfMlKem1024PrivateKeySeedPfx,
                MLKemTestDocuments.MLKem1024Content,
                null,
            ],
            [
                MLKemTestDocuments.MLKem1024WithUserKeyingMaterial,
                MLKemTestData.IetfMlKem1024PrivateKeySeedPfx,
                MLKemTestDocuments.MLKem1024Content,
                MLKemTestDocuments.MLKem1024UserKeyingMaterial,
            ],
        ];

        public static IEnumerable<object[]> MLKemAlternativeAlgorithmDocuments =>
        [
            [
                MLKemTestDocuments.MLKem768Aes192WrapWithHkdfSha256,
                Oids.HkdfWithSha256,
                Oids.Aes192Wrap,
                24,
            ],
            [
                MLKemTestDocuments.MLKem768Aes256WrapWithHkdfSha384,
                Oids.HkdfWithSha384,
                Oids.Aes256Wrap,
                32,
            ],
            [
                MLKemTestDocuments.MLKem768Aes256WrapWithHkdfSha512,
                Oids.HkdfWithSha512,
                Oids.Aes256Wrap,
                32,
            ],
            [
                MLKemTestDocuments.MLKem768Aes256WrapWithHkdfSha3_256,
                Oids.HkdfWithSha3_256,
                Oids.Aes256Wrap,
                32,
            ],
            [
                MLKemTestDocuments.MLKem768Aes256WrapWithHkdfSha3_384,
                Oids.HkdfWithSha3_384,
                Oids.Aes256Wrap,
                32,
            ],
            [
                MLKemTestDocuments.MLKem768Aes256WrapWithHkdfSha3_512,
                Oids.HkdfWithSha3_512,
                Oids.Aes256Wrap,
                32,
            ],
        ];

        [ConditionalTheory(typeof(MLKem), nameof(MLKem.IsSupported))]
        [MemberData(nameof(MLKemDocuments))]
        public static void DecodeMLKem(
            byte[] encodedMessage,
            string privateKeyPem,
            byte[] expectedContent,
            byte[]? expectedUserKeyingMaterial)
        {
            EnvelopedCms cms = new EnvelopedCms();
            cms.Decode(encodedMessage);

            KemRecipientInfo recipientInfo = Assert.IsType<KemRecipientInfo>(Assert.Single(cms.RecipientInfos));
            Assert.Equal(expectedUserKeyingMaterial, recipientInfo.UserKeyingMaterial?.ToArray());

            using (MLKem privateKey = MLKem.ImportFromPem(privateKeyPem))
            {
                cms.Decrypt(recipientInfo, privateKey);
            }

            Assert.Equal(expectedContent, cms.ContentInfo.Content);
        }

        [ConditionalTheory(typeof(PlatformSupport), nameof(PlatformSupport.IsPqcMLKemX509Supported))]
        [MemberData(nameof(MLKemCertificateDocuments))]
        public static void DecodeMLKemWithCertificate(
            byte[] encodedMessage,
            byte[] pfx,
            byte[] expectedContent,
            byte[]? expectedUserKeyingMaterial)
        {
            using (X509Certificate2 certificate = X509CertificateLoader.LoadPkcs12(
                pfx,
                MLKemTestData.EncryptedPrivateKeyPassword))
            {
                EnvelopedCms cms = new EnvelopedCms();
                cms.Decode(encodedMessage);
                KemRecipientInfo recipientInfo = Assert.IsType<KemRecipientInfo>(Assert.Single(cms.RecipientInfos));
                Assert.Equal(expectedUserKeyingMaterial, recipientInfo.UserKeyingMaterial?.ToArray());
                cms.Decrypt(new X509Certificate2Collection(certificate));

                Assert.Equal(expectedContent, cms.ContentInfo.Content);
            }
        }

        [ConditionalTheory(typeof(MLKem), nameof(MLKem.IsSupported))]
        [MemberData(nameof(MLKemAlternativeAlgorithmDocuments))]
        public static void DecodeMLKemWithAlternativeAlgorithms(
            byte[] encodedMessage,
            string expectedKdfOid,
            string expectedWrapOid,
            int expectedKekLength)
        {
            EnvelopedCms cms = new EnvelopedCms();
            cms.Decode(encodedMessage);

            KemRecipientInfo recipientInfo = Assert.IsType<KemRecipientInfo>(Assert.Single(cms.RecipientInfos));
            Assert.Equal(expectedKdfOid, recipientInfo.KeyDerivationAlgorithm.Oid.Value);
            Assert.Equal(expectedWrapOid, recipientInfo.KeyEncryptionAlgorithm.Oid.Value);
            Assert.Equal(expectedKekLength, recipientInfo.KeyEncryptionKeyLengthInBytes);
            Assert.Null(recipientInfo.UserKeyingMaterial);

            using (MLKem privateKey = MLKem.ImportFromPem(MLKemTestData.IetfMlKem768PrivateKeySeedPem))
            {
                cms.Decrypt(recipientInfo, privateKey);
            }

            Assert.Equal(MLKemTestDocuments.MLKem768Content, cms.ContentInfo.Content);
        }

        [ConditionalFact(typeof(MLKem), nameof(MLKem.IsSupported))]
        public static void DecodeMLKemWithoutKey()
        {
            EnvelopedCms cms = new EnvelopedCms();
            cms.Decode(MLKemTestDocuments.MLKem768WithoutUserKeyingMaterial);
            KemRecipientInfo recipientInfo = Assert.IsType<KemRecipientInfo>(Assert.Single(cms.RecipientInfos));

            Assert.Throws<CryptographicException>(() => cms.Decrypt(recipientInfo, (AsymmetricAlgorithm?)null));
        }
    }
}
