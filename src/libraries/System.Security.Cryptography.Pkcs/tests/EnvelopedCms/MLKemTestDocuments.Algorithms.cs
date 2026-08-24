// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;

namespace System.Security.Cryptography.Pkcs.EnvelopedCmsTests.Tests
{
    internal static partial class MLKemTestDocuments
    {
        // Generated with:
        // openssl cms -encrypt -binary -in content-768.txt -outform DER -out mlkem-768-aes192-hkdf-sha256.der -aes192-wrap -recip cert-768.pem -recip_kdf HKDF-SHA256
        internal static byte[] MLKem768Aes192WrapWithHkdfSha256 => field ??= Convert.FromBase64String(
            """
            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
            4FxuMsz+AUWStMYStqigEwzr18c=
            """);

        // Generated with:
        // openssl cms -encrypt -binary -in content-768.txt -outform DER -out mlkem-768-aes256-hkdf-sha384.der -aes256-wrap -recip cert-768.pem -recip_kdf HKDF-SHA384
        internal static byte[] MLKem768Aes256WrapWithHkdfSha384 => field ??= Convert.FromBase64String(
            """
            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
            dLUs9LT/p9A8Kfx6X1VcjP0OwTc=
            """);

        // Generated with:
        // openssl cms -encrypt -binary -in content-768.txt -outform DER -out mlkem-768-aes256-hkdf-sha512.der -aes256-wrap -recip cert-768.pem -recip_kdf HKDF-SHA512
        internal static byte[] MLKem768Aes256WrapWithHkdfSha512 => field ??= Convert.FromBase64String(
            """
            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
            22qqVlqTnYCMA/wWpceOQkTrCZQ=
            """);

        // Derived from an OpenSSL ML-KEM-768 AES-256-KW/HKDF-SHA256 document because OpenSSL 4.0.1 does not expose HKDF-SHA3 KDF names.
        internal static byte[] MLKem768Aes256WrapWithHkdfSha3_256 => field ??= Convert.FromBase64String(
            """
            MIIFVgYJKoZIhvcNAQcDoIIFRzCCBUMCAQMxggTupIIE6gYLKoZIhvcNAQkQDQMwggTZAgEAMDowIjENMAsGA1UEChMESUVURjER
            MA8GA1UEAxMITEFNUFMgV0cCFBWf/m8i/VzELFJN9v1eKNDeOPNPMAsGCWCGSAFlAwQEAgSCBEDlZbk0fPkEUCWa4fdCHrQdvPJy
            HFEZXFBxLAi2wQ3JyHAVKnyFJVmhpzbV1IfBVYXyA5vFrPBEKNpBbwMdnWWiTdclhB+XX9nrlXhsnAEFV9AB/r+uHDcE2wNIbFHs
            CKDtnzgX47sqCnBuV+R2/jDYY97GQS1jP+fNwBTGOVkZ4M+4OfaEsStzA9LPpn01DeDb/wENwsOSK/2z+2OgVMD59aSiOJaNlZ0V
            jdxRgsLndvilfSVreJXPSAxbaS/k4boYzN9lzkyTTFQf2VNHyWonlAhmpg/zTvXqRsM2M4epShyxzrOt4HJR9unTuQ31OuMlvm+j
            tZdarjcRhDlBr/xetrM6gH4C3obn6AEeHQjXmPEnahpGjhaEloHzsNjZyjNjULv+jzoxqdLguQiKIzduJ/KjqGaGjCuI17UCxAN4
            PsLaSv8C5ZLyXX1EWkebaE5flHDRCBwN6cVZKo7FP+JTSb0no5pVm+VMluVn7SKN/jB6xfQzrWL9wzYmGiogms9kj5xiqli38jYO
            y9c+HaMsx+mmSbha/JrEIvplBurExRiuEZn8SbyLjAtnHVbStnaGIsQ2QaQ5jkT59u8S7bMHPUbBG0OM16hVRQJBbKws6etDFBML
            zvugtLAJM6uSucXg4xa8pkC/Ga5YxdAMiN7LpkNwhuLcs8f/NLt3EnIY58SHzoZV1wyFAqwiluCDQU9V1Sc5+4Ol8sHmp3Ttt6V9
            gDa/S1eBHbSDXSARzrXVoTw6dVmZwsia4fO3qWlnU2fjvvOVuRQV/PC1ZlipQ85O3yYJet8glVHpAJ5ZB3ACuDT4Ezw/wd1cQDCq
            phoprBipPtfSuuc+56rISPmMHExz7K81qWcweiWHeMPIIKDjTL/ZkwtJWMA6oOQjcyuSFldhfoknGDutdSOPe+wHNNTNllQTlqK2
            oI0l1lDpPnjUKrEyzqfcJ9yY8bk27MjYrJmf8viCK7YR4uqTAXB1H+SH6ySJ+oTYaB9mV8MJprYPL0uoZ25lSA6T8eX936WBKN2U
            +ieZVWXb+cwW5V/mbzWvDGjyzLLOxfdiMJpwug2EK6qVfV5ulkw8SzpHgKIt666HQzEvE3sPtorlUICg/r7Bc72AV/0Z0yIXRRQq
            +It/q/o31pQ0gHfNOTosdKkQ9+Mdh6xAiTtBH/CpO9rnZ+pf7QTw16Bz6z4KEMuFDIJR3PKJUmbA2ffvFHjLwxzaEcWnoeTvlWwc
            6kw4xRukMunWgKU0q8ij9KsBz3CAKDFpwXv+UpbMEy45mSS/kDkPk61tjhXia95nHi4Tfu0EP1uLukgMjAenlHlXpLErTfGbN3Ny
            q0RG9ymBuKiESD0Y6n3GK5YQ7tgpD5k9LkZPLTCu8pt0Oyp1U+WCv1ShNYDZPaEH0i6ajjH9jT54shcOrKfN+YNn/YwfJ30AcVbq
            ZtmBFkcZ+X/wOzc5qmCRbp4wrjANBgsqhkiG9w0BCRADIQIBIDALBglghkgBZQMEAS0EKIjVGlYmOc/seKttMu+kGufWAb8p0SAl
            Wd16OZkM3q6m9FPjJX4FS+gwTAYJKoZIhvcNAQcBMB0GCWCGSAFlAwQBKgQQ0JykCyutY+3L4B4f2WF2jIAgpZYTDSZgdRIwZj67
            kpN7G/BoLO+Wx9S8tRRDMsD5e0c=
            """);

        internal static byte[] MLKem768Aes256WrapWithHkdfSha3_384 => field ??= Convert.FromBase64String(
            """
            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
            kpN7G/BoLO+Wx9S8tRRDMsD5e0c=
            """);

        internal static byte[] MLKem768Aes256WrapWithHkdfSha3_512 => field ??= Convert.FromBase64String(
            """
            MIIFVgYJKoZIhvcNAQcDoIIFRzCCBUMCAQMxggTupIIE6gYLKoZIhvcNAQkQDQMwggTZAgEAMDowIjENMAsGA1UEChMESUVURjER
            MA8GA1UEAxMITEFNUFMgV0cCFBWf/m8i/VzELFJN9v1eKNDeOPNPMAsGCWCGSAFlAwQEAgSCBEDlZbk0fPkEUCWa4fdCHrQdvPJy
            HFEZXFBxLAi2wQ3JyHAVKnyFJVmhpzbV1IfBVYXyA5vFrPBEKNpBbwMdnWWiTdclhB+XX9nrlXhsnAEFV9AB/r+uHDcE2wNIbFHs
            CKDtnzgX47sqCnBuV+R2/jDYY97GQS1jP+fNwBTGOVkZ4M+4OfaEsStzA9LPpn01DeDb/wENwsOSK/2z+2OgVMD59aSiOJaNlZ0V
            jdxRgsLndvilfSVreJXPSAxbaS/k4boYzN9lzkyTTFQf2VNHyWonlAhmpg/zTvXqRsM2M4epShyxzrOt4HJR9unTuQ31OuMlvm+j
            tZdarjcRhDlBr/xetrM6gH4C3obn6AEeHQjXmPEnahpGjhaEloHzsNjZyjNjULv+jzoxqdLguQiKIzduJ/KjqGaGjCuI17UCxAN4
            PsLaSv8C5ZLyXX1EWkebaE5flHDRCBwN6cVZKo7FP+JTSb0no5pVm+VMluVn7SKN/jB6xfQzrWL9wzYmGiogms9kj5xiqli38jYO
            y9c+HaMsx+mmSbha/JrEIvplBurExRiuEZn8SbyLjAtnHVbStnaGIsQ2QaQ5jkT59u8S7bMHPUbBG0OM16hVRQJBbKws6etDFBML
            zvugtLAJM6uSucXg4xa8pkC/Ga5YxdAMiN7LpkNwhuLcs8f/NLt3EnIY58SHzoZV1wyFAqwiluCDQU9V1Sc5+4Ol8sHmp3Ttt6V9
            gDa/S1eBHbSDXSARzrXVoTw6dVmZwsia4fO3qWlnU2fjvvOVuRQV/PC1ZlipQ85O3yYJet8glVHpAJ5ZB3ACuDT4Ezw/wd1cQDCq
            phoprBipPtfSuuc+56rISPmMHExz7K81qWcweiWHeMPIIKDjTL/ZkwtJWMA6oOQjcyuSFldhfoknGDutdSOPe+wHNNTNllQTlqK2
            oI0l1lDpPnjUKrEyzqfcJ9yY8bk27MjYrJmf8viCK7YR4uqTAXB1H+SH6ySJ+oTYaB9mV8MJprYPL0uoZ25lSA6T8eX936WBKN2U
            +ieZVWXb+cwW5V/mbzWvDGjyzLLOxfdiMJpwug2EK6qVfV5ulkw8SzpHgKIt666HQzEvE3sPtorlUICg/r7Bc72AV/0Z0yIXRRQq
            +It/q/o31pQ0gHfNOTosdKkQ9+Mdh6xAiTtBH/CpO9rnZ+pf7QTw16Bz6z4KEMuFDIJR3PKJUmbA2ffvFHjLwxzaEcWnoeTvlWwc
            6kw4xRukMunWgKU0q8ij9KsBz3CAKDFpwXv+UpbMEy45mSS/kDkPk61tjhXia95nHi4Tfu0EP1uLukgMjAenlHlXpLErTfGbN3Ny
            q0RG9ymBuKiESD0Y6n3GK5YQ7tgpD5k9LkZPLTCu8pt0Oyp1U+WCv1ShNYDZPaEH0i6ajjH9jT54shcOrKfN+YNn/YwfJ30AcVbq
            ZtmBFkcZ+X/wOzc5qmCRbp4wrjANBgsqhkiG9w0BCRADIwIBIDALBglghkgBZQMEAS0EKKAb6l/jk1UPjPKT/wZ3mJh6+n2lcz1Q
            6almqZHQqr9P5r/XPgSMthIwTAYJKoZIhvcNAQcBMB0GCWCGSAFlAwQBKgQQ0JykCyutY+3L4B4f2WF2jIAgpZYTDSZgdRIwZj67
            kpN7G/BoLO+Wx9S8tRRDMsD5e0c=
            """);
    }
}
