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

        [ConditionalFact(typeof(PlatformSupport), nameof(PlatformSupport.IsPqcMLKemX509Supported))]
        public static void RoundTripMLKem()
        {
            byte[] content = "Hello World ML-KEM round-trip"u8.ToArray();

            using (X509Certificate2 certificate = X509Certificate2.CreateFromPem(MLKemTestData.IetfMlKem768CertificatePem))
            {
                CmsRecipient recipient = CmsRecipient.CreateForKeyEncapsulation(certificate, ReadOnlySpan<byte>.Empty);
                EnvelopedCms cms = new EnvelopedCms(new ContentInfo(content));
                cms.Encrypt(recipient);
                byte[] encodedMessage = cms.Encode();

                cms = new EnvelopedCms();
                cms.Decode(encodedMessage);
                Assert.Equal(3, cms.Version);
                KemRecipientInfo recipientInfo = Assert.IsType<KemRecipientInfo>(Assert.Single(cms.RecipientInfos));
                ReadOnlyMemory<byte>? userKeyingMaterial = recipientInfo.UserKeyingMaterial;
                Assert.True(userKeyingMaterial.HasValue);
                Assert.True(userKeyingMaterial.Value.IsEmpty);

                using (MLKem privateKey = MLKem.ImportFromPem(MLKemTestData.IetfMlKem768PrivateKeySeedPem))
                {
                    cms.Decrypt(recipientInfo, privateKey);
                }

                Assert.Equal(content, cms.ContentInfo.Content);
            }
        }

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

        [ConditionalFact(typeof(MLKem), nameof(MLKem.IsSupported))]
        public static void DecodeMLKemWithWrongParameterSetPrivateKey()
        {
            EnvelopedCms cms = new EnvelopedCms();
            cms.Decode(MLKemTestDocuments.MLKem768WithoutUserKeyingMaterial);
            KemRecipientInfo recipientInfo = Assert.IsType<KemRecipientInfo>(Assert.Single(cms.RecipientInfos));

            using (MLKem privateKey = MLKem.ImportFromPem(MLKemTestData.IetfMlKem1024PrivateKeySeedPem))
            {
                Assert.Throws<CryptographicException>(() => cms.Decrypt(recipientInfo, privateKey));
            }
        }

        [ConditionalFact(typeof(MLKem), nameof(MLKem.IsSupported))]
        public static void DecodeMLKemWithWrongPrivateKey()
        {
            EnvelopedCms cms = new EnvelopedCms();
            cms.Decode(MLKemTestDocuments.MLKem768WithoutUserKeyingMaterial);
            KemRecipientInfo recipientInfo = Assert.IsType<KemRecipientInfo>(Assert.Single(cms.RecipientInfos));

            using (MLKem privateKey = MLKem.GenerateKey(MLKemAlgorithm.MLKem768))
            {
                Assert.ThrowsAny<CryptographicException>(() => cms.Decrypt(recipientInfo, privateKey));
            }
        }

        [ConditionalFact(typeof(MLKem), nameof(MLKem.IsSupported))]
        public static void DecodeMLKemWithTamperedCiphertext()
        {
            // Re-encoded with the first byte of KEMRecipientInfo.kemct changed from 0x0B to 0x0A.
            byte[] encodedMessage = Convert.FromBase64String(
                """
                MIIFVgYJKoZIhvcNAQcDoIIFRzCCBUMCAQMxggTupIIE6gYLKoZIhvcNAQkQDQMwggTZAgEAMDowIjENMAsGA1UEChMESUVURjER
                MA8GA1UEAxMITEFNUFMgV0cCFBWf/m8i/VzELFJN9v1eKNDeOPNPMAsGCWCGSAFlAwQEAgSCBEAK0VOJlqSEBRfo3SwOkh5kmCDj
                F9MhpWlrLCNlRqkEls+iPRKoZfn+bL6KZDO3VFZz4qPqLDjM8rGqrCgVd/d3KaU1+SfYhQC3oH567AvEJg2o+ppua1rV2dP6s+fS
                n8yhmJ6m1+jiLxaslWzooCWorcRgQtRR72VrX+U8kTIpDfjMHdmFuLvWgn7y0tDbM8Y7dd5MnNQs0opUmlK0LOID1xx//CJGQRkl
                fzrwKfn5g6qKnxzpJNG6guZrl7rKW7GTIpISxkuiNkj/9oZvTQZ4NdPAiEGzHOvTw/BC3Vh1lBL4/u6gbMGS9rrXip68Uc20U9ax
                lsXoy26/VeaoXWF7QyvlcjJZszs2kT9Jd0KyWyw+t/iV8pnde2h1UrWJf71zXx7BUxSjRjM2nFENAM2f0jvAODidZabvaY120To7
                +RBkZUj9lCndz2Q3fipMjmiI+5s+k7oEHi2d5wkcZhbJ2Vgs9hvH6BEypPd9TWLeCGlaP9rP59HGv0zsCZzhtGTZKLoa+5ldUx0p
                1ajfrbp2QRgHZE7U68zHhDx79/5jEWHI+2CUCXcNb9ANJ7IPiGf10oSgh3cZ49JJ49KzdXJimL/q/yY4JrX8l4GHtOEEwMw1Cp0k
                Bh9u2ex+S/TKnb6KZ4sxzEyB16+TpgTrZiamwxKiG7vARWHYEArdxJWWBhF16MB59N0/uXBiwIIyFplkI02MWTdQZHeKN5ki1AvQ
                coxGBrHvi7uRQa+zQl3npZih/z4auX5FY5rwqfYD+vAPAw2rZEhzpmI0M+zCcsHwIdnbVSEhK47cYXeR+cBUFbPmscAO9/31faBK
                CSgA8qsPwdE0KLezxS2T3fj8ytdnjyUjbVIJSG2Ij0/mXUjqiyBASU4h2/I94W1XS0sCkFAE1guVVoEsyZ7Okos4tlKl46N/U1Nc
                47X6yownb2dSyklDQa70kORBhfkE55FYCH/v/v1f6Ot4KTUPxX+hH/Lsofp+KhvfzX0KbLyC7bMomBS9bEYQLnChqgevIb21Flks
                hpjQZCMbAEQOYn2RnpuJ6KO57x+JkikmI/IfGLyZQ+dAUDw2EHSsiplEpvxX3E07ZVH/ZW88adP2yYH8YGhcT3QTkVi2UBopr1vY
                rVnWdPkQYhEwpuGN6HP263p0o/ZMRzctq7Ytjx5uNQtGYQSFivhnF33IRqKly/lMfIbJP1s7n2xvi0UcOH41B3RWmavgWABrQHhC
                1CR+FudHl+0E9froeNwkHIXMNeaWtEpbldPNF0bTvbp+TluHHdDgC9SA98vcQTo9DaPn6d8ZldzfmTO0+u3shEyYyWwLfqL1XZ2I
                EBfyOgTy3nvqawuYLvZC8yWlokYzaaYz4fCTiPCpGujm4JzY3r6w+yTgmkIOm+i/uNwhAqvFN34MhGIsWpM29e/xeTWpQs/y5Rlv
                drKkZvRFxDaxPRzp7X83frGx5TANBgsqhkiG9w0BCRADHAIBIDALBglghkgBZQMEAS0EKCJMyw6lqDPaNdBlM5mGk6XGWsYFa57/
                WBiykx+uk02o1gfdtbxVyqswTAYJKoZIhvcNAQcBMB0GCWCGSAFlAwQBKgQQimBaM3XSXzZUAwXXamkx6oAgeN8qo7seOz3ebMjm
                jQGY6kEyPuoLBGkzUu5M+0hnjRA=
                """);

            AssertMLKemDecryptionThrows(encodedMessage);
        }

        [ConditionalFact(typeof(MLKem), nameof(MLKem.IsSupported))]
        public static void DecodeMLKemWithTamperedWrappedKey()
        {
            // Re-encoded with the first byte of KEMRecipientInfo.encryptedKey changed from 0x22 to 0x23.
            byte[] encodedMessage = Convert.FromBase64String(
                """
                MIIFVgYJKoZIhvcNAQcDoIIFRzCCBUMCAQMxggTupIIE6gYLKoZIhvcNAQkQDQMwggTZAgEAMDowIjENMAsGA1UEChMESUVURjER
                MA8GA1UEAxMITEFNUFMgV0cCFBWf/m8i/VzELFJN9v1eKNDeOPNPMAsGCWCGSAFlAwQEAgSCBEAL0VOJlqSEBRfo3SwOkh5kmCDj
                F9MhpWlrLCNlRqkEls+iPRKoZfn+bL6KZDO3VFZz4qPqLDjM8rGqrCgVd/d3KaU1+SfYhQC3oH567AvEJg2o+ppua1rV2dP6s+fS
                n8yhmJ6m1+jiLxaslWzooCWorcRgQtRR72VrX+U8kTIpDfjMHdmFuLvWgn7y0tDbM8Y7dd5MnNQs0opUmlK0LOID1xx//CJGQRkl
                fzrwKfn5g6qKnxzpJNG6guZrl7rKW7GTIpISxkuiNkj/9oZvTQZ4NdPAiEGzHOvTw/BC3Vh1lBL4/u6gbMGS9rrXip68Uc20U9ax
                lsXoy26/VeaoXWF7QyvlcjJZszs2kT9Jd0KyWyw+t/iV8pnde2h1UrWJf71zXx7BUxSjRjM2nFENAM2f0jvAODidZabvaY120To7
                +RBkZUj9lCndz2Q3fipMjmiI+5s+k7oEHi2d5wkcZhbJ2Vgs9hvH6BEypPd9TWLeCGlaP9rP59HGv0zsCZzhtGTZKLoa+5ldUx0p
                1ajfrbp2QRgHZE7U68zHhDx79/5jEWHI+2CUCXcNb9ANJ7IPiGf10oSgh3cZ49JJ49KzdXJimL/q/yY4JrX8l4GHtOEEwMw1Cp0k
                Bh9u2ex+S/TKnb6KZ4sxzEyB16+TpgTrZiamwxKiG7vARWHYEArdxJWWBhF16MB59N0/uXBiwIIyFplkI02MWTdQZHeKN5ki1AvQ
                coxGBrHvi7uRQa+zQl3npZih/z4auX5FY5rwqfYD+vAPAw2rZEhzpmI0M+zCcsHwIdnbVSEhK47cYXeR+cBUFbPmscAO9/31faBK
                CSgA8qsPwdE0KLezxS2T3fj8ytdnjyUjbVIJSG2Ij0/mXUjqiyBASU4h2/I94W1XS0sCkFAE1guVVoEsyZ7Okos4tlKl46N/U1Nc
                47X6yownb2dSyklDQa70kORBhfkE55FYCH/v/v1f6Ot4KTUPxX+hH/Lsofp+KhvfzX0KbLyC7bMomBS9bEYQLnChqgevIb21Flks
                hpjQZCMbAEQOYn2RnpuJ6KO57x+JkikmI/IfGLyZQ+dAUDw2EHSsiplEpvxX3E07ZVH/ZW88adP2yYH8YGhcT3QTkVi2UBopr1vY
                rVnWdPkQYhEwpuGN6HP263p0o/ZMRzctq7Ytjx5uNQtGYQSFivhnF33IRqKly/lMfIbJP1s7n2xvi0UcOH41B3RWmavgWABrQHhC
                1CR+FudHl+0E9froeNwkHIXMNeaWtEpbldPNF0bTvbp+TluHHdDgC9SA98vcQTo9DaPn6d8ZldzfmTO0+u3shEyYyWwLfqL1XZ2I
                EBfyOgTy3nvqawuYLvZC8yWlokYzaaYz4fCTiPCpGujm4JzY3r6w+yTgmkIOm+i/uNwhAqvFN34MhGIsWpM29e/xeTWpQs/y5Rlv
                drKkZvRFxDaxPRzp7X83frGx5TANBgsqhkiG9w0BCRADHAIBIDALBglghkgBZQMEAS0EKCNMyw6lqDPaNdBlM5mGk6XGWsYFa57/
                WBiykx+uk02o1gfdtbxVyqswTAYJKoZIhvcNAQcBMB0GCWCGSAFlAwQBKgQQimBaM3XSXzZUAwXXamkx6oAgeN8qo7seOz3ebMjm
                jQGY6kEyPuoLBGkzUu5M+0hnjRA=
                """);

            AssertMLKemDecryptionThrows(encodedMessage);
        }

        [ConditionalFact(typeof(MLKem), nameof(MLKem.IsSupported))]
        public static void DecodeMLKemWithTamperedEncryptedContent()
        {
            // Re-encoded with the final byte of encryptedContent changed from 0x10 to 0x11.
            byte[] encodedMessage = Convert.FromBase64String(
                """
                MIIFVgYJKoZIhvcNAQcDoIIFRzCCBUMCAQMxggTupIIE6gYLKoZIhvcNAQkQDQMwggTZAgEAMDowIjENMAsGA1UEChMESUVURjER
                MA8GA1UEAxMITEFNUFMgV0cCFBWf/m8i/VzELFJN9v1eKNDeOPNPMAsGCWCGSAFlAwQEAgSCBEAL0VOJlqSEBRfo3SwOkh5kmCDj
                F9MhpWlrLCNlRqkEls+iPRKoZfn+bL6KZDO3VFZz4qPqLDjM8rGqrCgVd/d3KaU1+SfYhQC3oH567AvEJg2o+ppua1rV2dP6s+fS
                n8yhmJ6m1+jiLxaslWzooCWorcRgQtRR72VrX+U8kTIpDfjMHdmFuLvWgn7y0tDbM8Y7dd5MnNQs0opUmlK0LOID1xx//CJGQRkl
                fzrwKfn5g6qKnxzpJNG6guZrl7rKW7GTIpISxkuiNkj/9oZvTQZ4NdPAiEGzHOvTw/BC3Vh1lBL4/u6gbMGS9rrXip68Uc20U9ax
                lsXoy26/VeaoXWF7QyvlcjJZszs2kT9Jd0KyWyw+t/iV8pnde2h1UrWJf71zXx7BUxSjRjM2nFENAM2f0jvAODidZabvaY120To7
                +RBkZUj9lCndz2Q3fipMjmiI+5s+k7oEHi2d5wkcZhbJ2Vgs9hvH6BEypPd9TWLeCGlaP9rP59HGv0zsCZzhtGTZKLoa+5ldUx0p
                1ajfrbp2QRgHZE7U68zHhDx79/5jEWHI+2CUCXcNb9ANJ7IPiGf10oSgh3cZ49JJ49KzdXJimL/q/yY4JrX8l4GHtOEEwMw1Cp0k
                Bh9u2ex+S/TKnb6KZ4sxzEyB16+TpgTrZiamwxKiG7vARWHYEArdxJWWBhF16MB59N0/uXBiwIIyFplkI02MWTdQZHeKN5ki1AvQ
                coxGBrHvi7uRQa+zQl3npZih/z4auX5FY5rwqfYD+vAPAw2rZEhzpmI0M+zCcsHwIdnbVSEhK47cYXeR+cBUFbPmscAO9/31faBK
                CSgA8qsPwdE0KLezxS2T3fj8ytdnjyUjbVIJSG2Ij0/mXUjqiyBASU4h2/I94W1XS0sCkFAE1guVVoEsyZ7Okos4tlKl46N/U1Nc
                47X6yownb2dSyklDQa70kORBhfkE55FYCH/v/v1f6Ot4KTUPxX+hH/Lsofp+KhvfzX0KbLyC7bMomBS9bEYQLnChqgevIb21Flks
                hpjQZCMbAEQOYn2RnpuJ6KO57x+JkikmI/IfGLyZQ+dAUDw2EHSsiplEpvxX3E07ZVH/ZW88adP2yYH8YGhcT3QTkVi2UBopr1vY
                rVnWdPkQYhEwpuGN6HP263p0o/ZMRzctq7Ytjx5uNQtGYQSFivhnF33IRqKly/lMfIbJP1s7n2xvi0UcOH41B3RWmavgWABrQHhC
                1CR+FudHl+0E9froeNwkHIXMNeaWtEpbldPNF0bTvbp+TluHHdDgC9SA98vcQTo9DaPn6d8ZldzfmTO0+u3shEyYyWwLfqL1XZ2I
                EBfyOgTy3nvqawuYLvZC8yWlokYzaaYz4fCTiPCpGujm4JzY3r6w+yTgmkIOm+i/uNwhAqvFN34MhGIsWpM29e/xeTWpQs/y5Rlv
                drKkZvRFxDaxPRzp7X83frGx5TANBgsqhkiG9w0BCRADHAIBIDALBglghkgBZQMEAS0EKCJMyw6lqDPaNdBlM5mGk6XGWsYFa57/
                WBiykx+uk02o1gfdtbxVyqswTAYJKoZIhvcNAQcBMB0GCWCGSAFlAwQBKgQQimBaM3XSXzZUAwXXamkx6oAgeN8qo7seOz3ebMjm
                jQGY6kEyPuoLBGkzUu5M+0hnjRE=
                """);

            AssertMLKemDecryptionThrows(encodedMessage);
        }

        [ConditionalFact(typeof(PlatformSupport), nameof(PlatformSupport.IsPqcMLKemX509Supported))]
        public static void DecodeMLKemWithMatchingCertificateWithoutPrivateKey()
        {
            using (X509Certificate2 certificate = X509Certificate2.CreateFromPem(MLKemTestData.IetfMlKem768CertificatePem))
            {
                Assert.False(certificate.HasPrivateKey);

                EnvelopedCms cms = new EnvelopedCms();
                cms.Decode(MLKemTestDocuments.MLKem768WithoutUserKeyingMaterial);
                KemRecipientInfo recipientInfo = Assert.IsType<KemRecipientInfo>(Assert.Single(cms.RecipientInfos));
                Assert.True(recipientInfo.RecipientIdentifier.MatchesCertificate(certificate));

                X509Certificate2Collection extraStore = new X509Certificate2Collection(certificate);
                Assert.Throws<CryptographicException>(() => cms.Decrypt(recipientInfo, extraStore));
            }
        }

        [ConditionalFact(typeof(MLKem), nameof(MLKem.IsSupported))]
        public static void DecodeMLKemWithMultipleRecipients()
        {
            // Re-encoded with the KEM RecipientInfo duplicated in recipientInfos.
            byte[] encodedMessage = Convert.FromBase64String(
                """
                MIIKRAYJKoZIhvcNAQcDoIIKNTCCCjECAQMxggncpIIE6gYLKoZIhvcNAQkQDQMwggTZAgEAMDowIjENMAsGA1UEChMESUVURjER
                MA8GA1UEAxMITEFNUFMgV0cCFBWf/m8i/VzELFJN9v1eKNDeOPNPMAsGCWCGSAFlAwQEAgSCBEAL0VOJlqSEBRfo3SwOkh5kmCDj
                F9MhpWlrLCNlRqkEls+iPRKoZfn+bL6KZDO3VFZz4qPqLDjM8rGqrCgVd/d3KaU1+SfYhQC3oH567AvEJg2o+ppua1rV2dP6s+fS
                n8yhmJ6m1+jiLxaslWzooCWorcRgQtRR72VrX+U8kTIpDfjMHdmFuLvWgn7y0tDbM8Y7dd5MnNQs0opUmlK0LOID1xx//CJGQRkl
                fzrwKfn5g6qKnxzpJNG6guZrl7rKW7GTIpISxkuiNkj/9oZvTQZ4NdPAiEGzHOvTw/BC3Vh1lBL4/u6gbMGS9rrXip68Uc20U9ax
                lsXoy26/VeaoXWF7QyvlcjJZszs2kT9Jd0KyWyw+t/iV8pnde2h1UrWJf71zXx7BUxSjRjM2nFENAM2f0jvAODidZabvaY120To7
                +RBkZUj9lCndz2Q3fipMjmiI+5s+k7oEHi2d5wkcZhbJ2Vgs9hvH6BEypPd9TWLeCGlaP9rP59HGv0zsCZzhtGTZKLoa+5ldUx0p
                1ajfrbp2QRgHZE7U68zHhDx79/5jEWHI+2CUCXcNb9ANJ7IPiGf10oSgh3cZ49JJ49KzdXJimL/q/yY4JrX8l4GHtOEEwMw1Cp0k
                Bh9u2ex+S/TKnb6KZ4sxzEyB16+TpgTrZiamwxKiG7vARWHYEArdxJWWBhF16MB59N0/uXBiwIIyFplkI02MWTdQZHeKN5ki1AvQ
                coxGBrHvi7uRQa+zQl3npZih/z4auX5FY5rwqfYD+vAPAw2rZEhzpmI0M+zCcsHwIdnbVSEhK47cYXeR+cBUFbPmscAO9/31faBK
                CSgA8qsPwdE0KLezxS2T3fj8ytdnjyUjbVIJSG2Ij0/mXUjqiyBASU4h2/I94W1XS0sCkFAE1guVVoEsyZ7Okos4tlKl46N/U1Nc
                47X6yownb2dSyklDQa70kORBhfkE55FYCH/v/v1f6Ot4KTUPxX+hH/Lsofp+KhvfzX0KbLyC7bMomBS9bEYQLnChqgevIb21Flks
                hpjQZCMbAEQOYn2RnpuJ6KO57x+JkikmI/IfGLyZQ+dAUDw2EHSsiplEpvxX3E07ZVH/ZW88adP2yYH8YGhcT3QTkVi2UBopr1vY
                rVnWdPkQYhEwpuGN6HP263p0o/ZMRzctq7Ytjx5uNQtGYQSFivhnF33IRqKly/lMfIbJP1s7n2xvi0UcOH41B3RWmavgWABrQHhC
                1CR+FudHl+0E9froeNwkHIXMNeaWtEpbldPNF0bTvbp+TluHHdDgC9SA98vcQTo9DaPn6d8ZldzfmTO0+u3shEyYyWwLfqL1XZ2I
                EBfyOgTy3nvqawuYLvZC8yWlokYzaaYz4fCTiPCpGujm4JzY3r6w+yTgmkIOm+i/uNwhAqvFN34MhGIsWpM29e/xeTWpQs/y5Rlv
                drKkZvRFxDaxPRzp7X83frGx5TANBgsqhkiG9w0BCRADHAIBIDALBglghkgBZQMEAS0EKCJMyw6lqDPaNdBlM5mGk6XGWsYFa57/
                WBiykx+uk02o1gfdtbxVyqukggTqBgsqhkiG9w0BCRANAzCCBNkCAQAwOjAiMQ0wCwYDVQQKEwRJRVRGMREwDwYDVQQDEwhMQU1Q
                UyBXRwIUFZ/+byL9XMQsUk32/V4o0N44808wCwYJYIZIAWUDBAQCBIIEQAvRU4mWpIQFF+jdLA6SHmSYIOMX0yGlaWssI2VGqQSW
                z6I9Eqhl+f5svopkM7dUVnPio+osOMzysaqsKBV393cppTX5J9iFALegfnrsC8QmDaj6mm5rWtXZ0/qz59KfzKGYnqbX6OIvFqyV
                bOigJaitxGBC1FHvZWtf5TyRMikN+Mwd2YW4u9aCfvLS0Nszxjt13kyc1CzSilSaUrQs4gPXHH/8IkZBGSV/OvAp+fmDqoqfHOkk
                0bqC5muXuspbsZMikhLGS6I2SP/2hm9NBng108CIQbMc69PD8ELdWHWUEvj+7qBswZL2uteKnrxRzbRT1rGWxejLbr9V5qhdYXtD
                K+VyMlmzOzaRP0l3QrJbLD63+JXymd17aHVStYl/vXNfHsFTFKNGMzacUQ0AzZ/SO8A4OJ1lpu9pjXbROjv5EGRlSP2UKd3PZDd+
                KkyOaIj7mz6TugQeLZ3nCRxmFsnZWCz2G8foETKk931NYt4IaVo/2s/n0ca/TOwJnOG0ZNkouhr7mV1THSnVqN+tunZBGAdkTtTr
                zMeEPHv3/mMRYcj7YJQJdw1v0A0nsg+IZ/XShKCHdxnj0knj0rN1cmKYv+r/JjgmtfyXgYe04QTAzDUKnSQGH27Z7H5L9Mqdvopn
                izHMTIHXr5OmBOtmJqbDEqIbu8BFYdgQCt3ElZYGEXXowHn03T+5cGLAgjIWmWQjTYxZN1Bkd4o3mSLUC9ByjEYGse+Lu5FBr7NC
                XeelmKH/Phq5fkVjmvCp9gP68A8DDatkSHOmYjQz7MJywfAh2dtVISErjtxhd5H5wFQVs+axwA73/fV9oEoJKADyqw/B0TQot7PF
                LZPd+PzK12ePJSNtUglIbYiPT+ZdSOqLIEBJTiHb8j3hbVdLSwKQUATWC5VWgSzJns6Sizi2UqXjo39TU1zjtfrKjCdvZ1LKSUNB
                rvSQ5EGF+QTnkVgIf+/+/V/o63gpNQ/Ff6Ef8uyh+n4qG9/NfQpsvILtsyiYFL1sRhAucKGqB68hvbUWWSyGmNBkIxsARA5ifZGe
                m4noo7nvH4mSKSYj8h8YvJlD50BQPDYQdKyKmUSm/FfcTTtlUf9lbzxp0/bJgfxgaFxPdBORWLZQGimvW9itWdZ0+RBiETCm4Y3o
                c/brenSj9kxHNy2rti2PHm41C0ZhBIWK+GcXfchGoqXL+Ux8hsk/WzufbG+LRRw4fjUHdFaZq+BYAGtAeELUJH4W50eX7QT1+uh4
                3CQchcw15pa0SluV080XRtO9un5OW4cd0OAL1ID3y9xBOj0No+fp3xmV3N+ZM7T67eyETJjJbAt+ovVdnYgQF/I6BPLee+prC5gu
                9kLzJaWiRjNppjPh8JOI8Kka6ObgnNjevrD7JOCaQg6b6L+43CECq8U3fgyEYixakzb17/F5NalCz/LlGW92sqRm9EXENrE9HOnt
                fzd+sbHlMA0GCyqGSIb3DQEJEAMcAgEgMAsGCWCGSAFlAwQBLQQoIkzLDqWoM9o10GUzmYaTpcZaxgVrnv9YGLKTH66TTajWB921
                vFXKqzBMBgkqhkiG9w0BBwEwHQYJYIZIAWUDBAEqBBCKYFozddJfNlQDBddqaTHqgCB43yqjux47Pd5syOaNAZjqQTI+6gsEaTNS
                7kz7SGeNEA==
                """);

            using (MLKem privateKey = MLKem.ImportFromPem(MLKemTestData.IetfMlKem768PrivateKeySeedPem))
            {
                for (int index = 0; index < 2; index++)
                {
                    EnvelopedCms cms = new EnvelopedCms();
                    cms.Decode(encodedMessage);
                    Assert.Equal(2, cms.RecipientInfos.Count);
                    KemRecipientInfo recipientInfo = Assert.IsType<KemRecipientInfo>(cms.RecipientInfos[index]);
                    cms.Decrypt(recipientInfo, privateKey);
                    Assert.Equal(MLKemTestDocuments.MLKem768Content, cms.ContentInfo.Content);
                }
            }
        }

        private static void AssertMLKemDecryptionThrows(byte[] encodedMessage)
        {
            EnvelopedCms cms = new EnvelopedCms();
            cms.Decode(encodedMessage);
            KemRecipientInfo recipientInfo = Assert.IsType<KemRecipientInfo>(Assert.Single(cms.RecipientInfos));

            using (MLKem privateKey = MLKem.ImportFromPem(MLKemTestData.IetfMlKem768PrivateKeySeedPem))
            {
                Assert.ThrowsAny<CryptographicException>(() => cms.Decrypt(recipientInfo, privateKey));
            }
        }
    }
}
