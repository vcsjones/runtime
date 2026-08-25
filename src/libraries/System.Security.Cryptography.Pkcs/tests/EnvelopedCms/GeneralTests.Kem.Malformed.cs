// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security.Cryptography.Tests;
using Xunit;

namespace System.Security.Cryptography.Pkcs.EnvelopedCmsTests.Tests
{
    public static partial class GeneralTests
    {
        [ConditionalFact(typeof(MLKem), nameof(MLKem.IsSupported))]
        public static void DecodeMLKemWithInvalidKemCiphertextLength()
        {
            // Uses an ML-KEM-768 ciphertext that is 1,087 bytes instead of 1,088 bytes.
            byte[] encodedMessage = Convert.FromBase64String(
                """
                MIIFVQYJKoZIhvcNAQcDoIIFRjCCBUICAQMxggTtpIIE6QYLKoZIhvcNAQkQDQMwggTYAgEAMDowIjENMAsGA1UEChMESUVURjER
                MA8GA1UEAxMITEFNUFMgV0cCFBWf/m8i/VzELFJN9v1eKNDeOPNPMAsGCWCGSAFlAwQEAgSCBD8L0VOJlqSEBRfo3SwOkh5kmCDj
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
                drKkZvRFxDaxPRzp7X83frGxMA0GCyqGSIb3DQEJEAMcAgEgMAsGCWCGSAFlAwQBLQQoIkzLDqWoM9o10GUzmYaTpcZaxgVrnv9Y
                GLKTH66TTajWB921vFXKqzBMBgkqhkiG9w0BBwEwHQYJYIZIAWUDBAEqBBCKYFozddJfNlQDBddqaTHqgCB43yqjux47Pd5syOaN
                AZjqQTI+6gsEaTNS7kz7SGeNEA==
                """);

            AssertMLKemDecryptionFails(encodedMessage);
        }

        [ConditionalFact(typeof(MLKem), nameof(MLKem.IsSupported))]
        public static void DecodeMLKemWithEncryptedKeyTooShort()
        {
            // Uses a wrapped key that is 23 bytes, below the 24-byte minimum.
            byte[] encodedMessage = Convert.FromBase64String(
                """
                MIIFRQYJKoZIhvcNAQcDoIIFNjCCBTICAQMxggTdpIIE2QYLKoZIhvcNAQkQDQMwggTIAgEAMDowIjENMAsGA1UEChMESUVURjER
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
                drKkZvRFxDaxPRzp7X83frGx5TANBgsqhkiG9w0BCRADHAIBIDALBglghkgBZQMEAS0EFyJMyw6lqDPaNdBlM5mGk6XGWsYFa57/
                MEwGCSqGSIb3DQEHATAdBglghkgBZQMEASoEEIpgWjN10l82VAMF12ppMeqAIHjfKqO7Hjs93mzI5o0BmOpBMj7qCwRpM1LuTPtI
                Z40Q
                """);

            AssertMLKemDecryptionFails(encodedMessage);
        }

        [ConditionalFact(typeof(MLKem), nameof(MLKem.IsSupported))]
        public static void DecodeMLKemWithEncryptedKeyNotBlockAligned()
        {
            // Uses a wrapped key that is 25 bytes, which is not divisible by 8.
            byte[] encodedMessage = Convert.FromBase64String(
                """
                MIIFRwYJKoZIhvcNAQcDoIIFODCCBTQCAQMxggTfpIIE2wYLKoZIhvcNAQkQDQMwggTKAgEAMDowIjENMAsGA1UEChMESUVURjER
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
                drKkZvRFxDaxPRzp7X83frGx5TANBgsqhkiG9w0BCRADHAIBIDALBglghkgBZQMEAS0EGSJMyw6lqDPaNdBlM5mGk6XGWsYFa57/
                WBgwTAYJKoZIhvcNAQcBMB0GCWCGSAFlAwQBKgQQimBaM3XSXzZUAwXXamkx6oAgeN8qo7seOz3ebMjmjQGY6kEyPuoLBGkzUu5M
                +0hnjRA=
                """);

            AssertMLKemDecryptionFails(encodedMessage);
        }

        [ConditionalFact(typeof(MLKem), nameof(MLKem.IsSupported))]
        public static void DecodeMLKemWithMismatchedKekLength()
        {
            // Declares a 16-byte KEK while using AES-256 Key Wrap, which requires 32 bytes.
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
                drKkZvRFxDaxPRzp7X83frGx5TANBgsqhkiG9w0BCRADHAIBEDALBglghkgBZQMEAS0EKCJMyw6lqDPaNdBlM5mGk6XGWsYFa57/
                WBiykx+uk02o1gfdtbxVyqswTAYJKoZIhvcNAQcBMB0GCWCGSAFlAwQBKgQQimBaM3XSXzZUAwXXamkx6oAgeN8qo7seOz3ebMjm
                jQGY6kEyPuoLBGkzUu5M+0hnjRA=
                """);

            AssertMLKemDecryptionFails(encodedMessage);
        }

        [ConditionalFact(typeof(MLKem), nameof(MLKem.IsSupported))]
        public static void DecodeMLKemWithUnknownKemAlgorithm()
        {
            // Uses KEM algorithm OID 1.2.3.4.1.
            byte[] encodedMessage = Convert.FromBase64String(
                """
                MIIFUQYJKoZIhvcNAQcDoIIFQjCCBT4CAQMxggTppIIE5QYLKoZIhvcNAQkQDQMwggTUAgEAMDowIjENMAsGA1UEChMESUVURjER
                MA8GA1UEAxMITEFNUFMgV0cCFBWf/m8i/VzELFJN9v1eKNDeOPNPMAYGBCoDBAEEggRAC9FTiZakhAUX6N0sDpIeZJgg4xfTIaVp
                aywjZUapBJbPoj0SqGX5/my+imQzt1RWc+Kj6iw4zPKxqqwoFXf3dymlNfkn2IUAt6B+euwLxCYNqPqabmta1dnT+rPn0p/MoZie
                ptfo4i8WrJVs6KAlqK3EYELUUe9la1/lPJEyKQ34zB3Zhbi71oJ+8tLQ2zPGO3XeTJzULNKKVJpStCziA9ccf/wiRkEZJX868Cn5
                +YOqip8c6STRuoLma5e6yluxkyKSEsZLojZI//aGb00GeDXTwIhBsxzr08PwQt1YdZQS+P7uoGzBkva614qevFHNtFPWsZbF6Mtu
                v1XmqF1he0Mr5XIyWbM7NpE/SXdCslssPrf4lfKZ3XtodVK1iX+9c18ewVMUo0YzNpxRDQDNn9I7wDg4nWWm72mNdtE6O/kQZGVI
                /ZQp3c9kN34qTI5oiPubPpO6BB4tnecJHGYWydlYLPYbx+gRMqT3fU1i3ghpWj/az+fRxr9M7Amc4bRk2Si6GvuZXVMdKdWo3626
                dkEYB2RO1OvMx4Q8e/f+YxFhyPtglAl3DW/QDSeyD4hn9dKEoId3GePSSePSs3VyYpi/6v8mOCa1/JeBh7ThBMDMNQqdJAYfbtns
                fkv0yp2+imeLMcxMgdevk6YE62YmpsMSohu7wEVh2BAK3cSVlgYRdejAefTdP7lwYsCCMhaZZCNNjFk3UGR3ijeZItQL0HKMRgax
                74u7kUGvs0Jd56WYof8+Grl+RWOa8Kn2A/rwDwMNq2RIc6ZiNDPswnLB8CHZ21UhISuO3GF3kfnAVBWz5rHADvf99X2gSgkoAPKr
                D8HRNCi3s8Utk934/MrXZ48lI21SCUhtiI9P5l1I6osgQElOIdvyPeFtV0tLApBQBNYLlVaBLMmezpKLOLZSpeOjf1NTXOO1+sqM
                J29nUspJQ0Gu9JDkQYX5BOeRWAh/7/79X+jreCk1D8V/oR/y7KH6fiob3819Cmy8gu2zKJgUvWxGEC5woaoHryG9tRZZLIaY0GQj
                GwBEDmJ9kZ6bieijue8fiZIpJiPyHxi8mUPnQFA8NhB0rIqZRKb8V9xNO2VR/2VvPGnT9smB/GBoXE90E5FYtlAaKa9b2K1Z1nT5
                EGIRMKbhjehz9ut6dKP2TEc3Lau2LY8ebjULRmEEhYr4Zxd9yEaipcv5THyGyT9bO59sb4tFHDh+NQd0Vpmr4FgAa0B4QtQkfhbn
                R5ftBPX66HjcJByFzDXmlrRKW5XTzRdG0726fk5bhx3Q4AvUgPfL3EE6PQ2j5+nfGZXc35kztPrt7IRMmMlsC36i9V2diBAX8joE
                8t576msLmC72QvMlpaJGM2mmM+Hwk4jwqRro5uCc2N6+sPsk4JpCDpvov7jcIQKrxTd+DIRiLFqTNvXv8Xk1qULP8uUZb3aypGb0
                RcQ2sT0c6e1/N36xseUwDQYLKoZIhvcNAQkQAxwCASAwCwYJYIZIAWUDBAEtBCgiTMsOpagz2jXQZTOZhpOlxlrGBWue/1gYspMf
                rpNNqNYH3bW8VcqrMEwGCSqGSIb3DQEHATAdBglghkgBZQMEASoEEIpgWjN10l82VAMF12ppMeqAIHjfKqO7Hjs93mzI5o0BmOpB
                Mj7qCwRpM1LuTPtIZ40Q
                """);

            AssertMLKemDecryptionFails(encodedMessage);
        }

        [ConditionalFact(typeof(MLKem), nameof(MLKem.IsSupported))]
        public static void DecodeMLKemWithUnknownKdfAlgorithm()
        {
            // Uses KDF algorithm OID 1.2.3.4.2.
            byte[] encodedMessage = Convert.FromBase64String(
                """
                MIIFTwYJKoZIhvcNAQcDoIIFQDCCBTwCAQMxggTnpIIE4wYLKoZIhvcNAQkQDQMwggTSAgEAMDowIjENMAsGA1UEChMESUVURjER
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
                drKkZvRFxDaxPRzp7X83frGx5TAGBgQqAwQCAgEgMAsGCWCGSAFlAwQBLQQoIkzLDqWoM9o10GUzmYaTpcZaxgVrnv9YGLKTH66T
                TajWB921vFXKqzBMBgkqhkiG9w0BBwEwHQYJYIZIAWUDBAEqBBCKYFozddJfNlQDBddqaTHqgCB43yqjux47Pd5syOaNAZjqQTI+
                6gsEaTNS7kz7SGeNEA==
                """);

            AssertMLKemDecryptionFails(encodedMessage);
        }

        [ConditionalFact(typeof(MLKem), nameof(MLKem.IsSupported))]
        public static void DecodeMLKemWithUnknownWrapAlgorithm()
        {
            // Uses key-wrap algorithm OID 1.2.3.4.3.
            byte[] encodedMessage = Convert.FromBase64String(
                """
                MIIFUQYJKoZIhvcNAQcDoIIFQjCCBT4CAQMxggTppIIE5QYLKoZIhvcNAQkQDQMwggTUAgEAMDowIjENMAsGA1UEChMESUVURjER
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
                drKkZvRFxDaxPRzp7X83frGx5TANBgsqhkiG9w0BCRADHAIBIDAGBgQqAwQDBCgiTMsOpagz2jXQZTOZhpOlxlrGBWue/1gYspMf
                rpNNqNYH3bW8VcqrMEwGCSqGSIb3DQEHATAdBglghkgBZQMEASoEEIpgWjN10l82VAMF12ppMeqAIHjfKqO7Hjs93mzI5o0BmOpB
                Mj7qCwRpM1LuTPtIZ40Q
                """);

            AssertMLKemDecryptionFails(encodedMessage);
        }

        [Fact]
        public static void DecodeMLKemWithInvalidOriValue()
        {
            // Encodes oriValue as a UTF8String instead of a KEMRecipientInfo SEQUENCE.
            byte[] encodedMessage = Convert.FromBase64String(
                """
                MIGEBgkqhkiG9w0BBwOgdzB1AgEDMSKkIAYLKoZIhvcNAQkQDQMMEWNvcnJ1cHQgb3JpIHZhbHVlMEwGCSqGSIb3DQEHATAdBglg
                hkgBZQMEASoEEIpgWjN10l82VAMF12ppMeqAIHjfKqO7Hjs93mzI5o0BmOpBMj7qCwRpM1LuTPtIZ40Q
                """);

            EnvelopedCms cms = new EnvelopedCms();
            Assert.Throws<CryptographicException>(() => cms.Decode(encodedMessage));
        }

        [ConditionalFact(typeof(MLKem), nameof(MLKem.IsSupported))]
        public static void DecodeMLKemInvalidVersion()
        {
            // Uses KEMRecipientInfo version 1 instead of version 0.
            byte[] encodedMessage = Convert.FromBase64String(
                """
                MIIFVgYJKoZIhvcNAQcDoIIFRzCCBUMCAQMxggTupIIE6gYLKoZIhvcNAQkQDQMwggTZAgEBMDowIjENMAsGA1UEChMESUVURjER
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
                jQGY6kEyPuoLBGkzUu5M+0hnjRA=
                """);

            EnvelopedCms cms = new EnvelopedCms();
            cms.Decode(encodedMessage);
            KemRecipientInfo recipientInfo = Assert.IsType<KemRecipientInfo>(Assert.Single(cms.RecipientInfos));
            Assert.Equal(1, recipientInfo.Version);

            using (MLKem privateKey = MLKem.ImportFromPem(MLKemTestData.IetfMlKem768PrivateKeySeedPem))
            {
                Assert.Throws<CryptographicException>(() => cms.Decrypt(recipientInfo, privateKey));
            }
        }

        [ConditionalFact(typeof(MLKem), nameof(MLKem.IsSupported))]
        public static void DecodeMLKemWithKemParameters()
        {
            // Encodes DER NULL parameters in the KEM AlgorithmIdentifier.
            byte[] encodedMessage = Convert.FromBase64String(
                """
                MIIFWAYJKoZIhvcNAQcDoIIFSTCCBUUCAQMxggTwpIIE7AYLKoZIhvcNAQkQDQMwggTbAgEAMDowIjENMAsGA1UEChMESUVURjER
                MA8GA1UEAxMITEFNUFMgV0cCFBWf/m8i/VzELFJN9v1eKNDeOPNPMA0GCWCGSAFlAwQEAgUABIIEQAvRU4mWpIQFF+jdLA6SHmSY
                IOMX0yGlaWssI2VGqQSWz6I9Eqhl+f5svopkM7dUVnPio+osOMzysaqsKBV393cppTX5J9iFALegfnrsC8QmDaj6mm5rWtXZ0/qz
                59KfzKGYnqbX6OIvFqyVbOigJaitxGBC1FHvZWtf5TyRMikN+Mwd2YW4u9aCfvLS0Nszxjt13kyc1CzSilSaUrQs4gPXHH/8IkZB
                GSV/OvAp+fmDqoqfHOkk0bqC5muXuspbsZMikhLGS6I2SP/2hm9NBng108CIQbMc69PD8ELdWHWUEvj+7qBswZL2uteKnrxRzbRT
                1rGWxejLbr9V5qhdYXtDK+VyMlmzOzaRP0l3QrJbLD63+JXymd17aHVStYl/vXNfHsFTFKNGMzacUQ0AzZ/SO8A4OJ1lpu9pjXbR
                Ojv5EGRlSP2UKd3PZDd+KkyOaIj7mz6TugQeLZ3nCRxmFsnZWCz2G8foETKk931NYt4IaVo/2s/n0ca/TOwJnOG0ZNkouhr7mV1T
                HSnVqN+tunZBGAdkTtTrzMeEPHv3/mMRYcj7YJQJdw1v0A0nsg+IZ/XShKCHdxnj0knj0rN1cmKYv+r/JjgmtfyXgYe04QTAzDUK
                nSQGH27Z7H5L9MqdvopnizHMTIHXr5OmBOtmJqbDEqIbu8BFYdgQCt3ElZYGEXXowHn03T+5cGLAgjIWmWQjTYxZN1Bkd4o3mSLU
                C9ByjEYGse+Lu5FBr7NCXeelmKH/Phq5fkVjmvCp9gP68A8DDatkSHOmYjQz7MJywfAh2dtVISErjtxhd5H5wFQVs+axwA73/fV9
                oEoJKADyqw/B0TQot7PFLZPd+PzK12ePJSNtUglIbYiPT+ZdSOqLIEBJTiHb8j3hbVdLSwKQUATWC5VWgSzJns6Sizi2UqXjo39T
                U1zjtfrKjCdvZ1LKSUNBrvSQ5EGF+QTnkVgIf+/+/V/o63gpNQ/Ff6Ef8uyh+n4qG9/NfQpsvILtsyiYFL1sRhAucKGqB68hvbUW
                WSyGmNBkIxsARA5ifZGem4noo7nvH4mSKSYj8h8YvJlD50BQPDYQdKyKmUSm/FfcTTtlUf9lbzxp0/bJgfxgaFxPdBORWLZQGimv
                W9itWdZ0+RBiETCm4Y3oc/brenSj9kxHNy2rti2PHm41C0ZhBIWK+GcXfchGoqXL+Ux8hsk/WzufbG+LRRw4fjUHdFaZq+BYAGtA
                eELUJH4W50eX7QT1+uh43CQchcw15pa0SluV080XRtO9un5OW4cd0OAL1ID3y9xBOj0No+fp3xmV3N+ZM7T67eyETJjJbAt+ovVd
                nYgQF/I6BPLee+prC5gu9kLzJaWiRjNppjPh8JOI8Kka6ObgnNjevrD7JOCaQg6b6L+43CECq8U3fgyEYixakzb17/F5NalCz/Ll
                GW92sqRm9EXENrE9HOntfzd+sbHlMA0GCyqGSIb3DQEJEAMcAgEgMAsGCWCGSAFlAwQBLQQoIkzLDqWoM9o10GUzmYaTpcZaxgVr
                nv9YGLKTH66TTajWB921vFXKqzBMBgkqhkiG9w0BBwEwHQYJYIZIAWUDBAEqBBCKYFozddJfNlQDBddqaTHqgCB43yqjux47Pd5s
                yOaNAZjqQTI+6gsEaTNS7kz7SGeNEA==
                """);

            AssertMLKemDecryptionFails(encodedMessage);
        }

        [ConditionalFact(typeof(MLKem), nameof(MLKem.IsSupported))]
        public static void DecodeMLKemWithKdfParameters()
        {
            // Encodes DER NULL parameters in the KDF AlgorithmIdentifier.
            byte[] encodedMessage = Convert.FromBase64String(
                """
                MIIFWAYJKoZIhvcNAQcDoIIFSTCCBUUCAQMxggTwpIIE7AYLKoZIhvcNAQkQDQMwggTbAgEAMDowIjENMAsGA1UEChMESUVURjER
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
                drKkZvRFxDaxPRzp7X83frGx5TAPBgsqhkiG9w0BCRADHAUAAgEgMAsGCWCGSAFlAwQBLQQoIkzLDqWoM9o10GUzmYaTpcZaxgVr
                nv9YGLKTH66TTajWB921vFXKqzBMBgkqhkiG9w0BBwEwHQYJYIZIAWUDBAEqBBCKYFozddJfNlQDBddqaTHqgCB43yqjux47Pd5s
                yOaNAZjqQTI+6gsEaTNS7kz7SGeNEA==
                """);

            AssertMLKemDecryptionFails(encodedMessage);
        }

        [ConditionalFact(typeof(MLKem), nameof(MLKem.IsSupported))]
        public static void DecodeMLKemWithWrapParameters()
        {
            // Encodes DER NULL parameters in the key-wrap AlgorithmIdentifier.
            byte[] encodedMessage = Convert.FromBase64String(
                """
                MIIFWAYJKoZIhvcNAQcDoIIFSTCCBUUCAQMxggTwpIIE7AYLKoZIhvcNAQkQDQMwggTbAgEAMDowIjENMAsGA1UEChMESUVURjER
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
                drKkZvRFxDaxPRzp7X83frGx5TANBgsqhkiG9w0BCRADHAIBIDANBglghkgBZQMEAS0FAAQoIkzLDqWoM9o10GUzmYaTpcZaxgVr
                nv9YGLKTH66TTajWB921vFXKqzBMBgkqhkiG9w0BBwEwHQYJYIZIAWUDBAEqBBCKYFozddJfNlQDBddqaTHqgCB43yqjux47Pd5s
                yOaNAZjqQTI+6gsEaTNS7kz7SGeNEA==
                """);

            AssertMLKemDecryptionFails(encodedMessage);
        }

        private static void AssertMLKemDecryptionFails(byte[] encodedMessage)
        {
            EnvelopedCms cms = new EnvelopedCms();
            cms.Decode(encodedMessage);
            KemRecipientInfo recipientInfo = Assert.IsType<KemRecipientInfo>(Assert.Single(cms.RecipientInfos));

            using (MLKem privateKey = MLKem.ImportFromPem(MLKemTestData.IetfMlKem768PrivateKeySeedPem))
            {
                Assert.Throws<CryptographicException>(() => cms.Decrypt(recipientInfo, privateKey));
            }
        }
    }
}
