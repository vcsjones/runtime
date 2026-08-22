// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Security.Cryptography.Tests;
using System.Security.Cryptography.X509Certificates;
using Xunit;

using Test.Cryptography;

namespace System.Security.Cryptography.Pkcs.EnvelopedCmsTests.Tests
{
    public static partial class GeneralTests
    {
        public static IEnumerable<object[]> MLKemDocumentsWithoutUserKeyingMaterial =>
        [
            [
                MLKemTestDocuments.MLKem512WithoutUserKeyingMaterial,
                MLKemTestData.IetfMlKem512PrivateKeySeedPem,
                MLKemTestDocuments.MLKem512Content,
            ],
            [
                MLKemTestDocuments.MLKem768WithoutUserKeyingMaterial,
                MLKemTestData.IetfMlKem768PrivateKeySeedPem,
                MLKemTestDocuments.MLKem768Content,
            ],
            [
                MLKemTestDocuments.MLKem1024WithoutUserKeyingMaterial,
                MLKemTestData.IetfMlKem1024PrivateKeySeedPem,
                MLKemTestDocuments.MLKem1024Content,
            ],
        ];

        public static IEnumerable<object[]> MLKemCertificateDocumentsWithoutUserKeyingMaterial =>
        [
            [
                MLKemTestDocuments.MLKem512WithoutUserKeyingMaterial,
                MLKemTestData.IetfMlKem512PrivateKeySeedPfx,
                MLKemTestDocuments.MLKem512Content,
            ],
            [
                MLKemTestDocuments.MLKem768WithoutUserKeyingMaterial,
                MLKemTestData.IetfMlKem768PrivateKeySeedPfx,
                MLKemTestDocuments.MLKem768Content,
            ],
            [
                MLKemTestDocuments.MLKem1024WithoutUserKeyingMaterial,
                MLKemTestData.IetfMlKem1024PrivateKeySeedPfx,
                MLKemTestDocuments.MLKem1024Content,
            ],
        ];

        [ConditionalTheory(typeof(MLKem), nameof(MLKem.IsSupported))]
        [MemberData(nameof(MLKemDocumentsWithoutUserKeyingMaterial))]
        public static void DecodeMLKem(byte[] encodedMessage, string privateKeyPem, byte[] expectedContent)
        {
            EnvelopedCms cms = new EnvelopedCms();
            cms.Decode(encodedMessage);

            KemRecipientInfo recipientInfo = Assert.IsType<KemRecipientInfo>(Assert.Single(cms.RecipientInfos));

            using (MLKem privateKey = MLKem.ImportFromPem(privateKeyPem))
            {
                cms.Decrypt(recipientInfo, privateKey);
            }

            Assert.Equal(expectedContent, cms.ContentInfo.Content);
        }

        [ConditionalTheory(typeof(PlatformSupport), nameof(PlatformSupport.IsPqcMLKemX509Supported))]
        [MemberData(nameof(MLKemCertificateDocumentsWithoutUserKeyingMaterial))]
        public static void DecodeMLKemWithCertificate(byte[] encodedMessage, byte[] pfx, byte[] expectedContent)
        {
            using (X509Certificate2 certificate = X509CertificateLoader.LoadPkcs12(
                pfx,
                MLKemTestData.EncryptedPrivateKeyPassword))
            {
                EnvelopedCms cms = new EnvelopedCms();
                cms.Decode(encodedMessage);
                cms.Decrypt(new X509Certificate2Collection(certificate));

                Assert.Equal(expectedContent, cms.ContentInfo.Content);
            }
        }
    }
}
