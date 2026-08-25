// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;

namespace System.Security.Cryptography.Pkcs.EnvelopedCmsTests.Tests
{
    internal static partial class MLKemTestDocuments
    {
        internal static byte[] MLKem512Content => field ??= "Hello World ML-KEM-512"u8.ToArray();

        internal static byte[] MLKem512UserKeyingMaterial => field ??= "ML-KEM-512:ML-KEM-512"u8.ToArray();

        // Generated with:
        // openssl cms -encrypt -binary -in content-512.txt -outform DER -out mlkem-512-without-ukm.der -aes128-wrap -recip cert-512.pem -recip_kdf HKDF-SHA256
        internal static byte[] MLKem512WithoutUserKeyingMaterial => field ??= Convert.FromBase64String(
            """
            MIIEFgYJKoZIhvcNAQcDoIIEBzCCBAMCAQMxggOupIIDqgYLKoZIhvcNAQkQDQMwggOZAgEAMDowIjENMAsGA1UEChMESUVURjER
            MA8GA1UEAxMITEFNUFMgV0cCFBWf/m8i/VzELFJN9v1eKNDeOPNPMAsGCWCGSAFlAwQEAQSCAwC+JtTE+1AD/ZlXJo3dUMi8Feeb
            KRAmnT7EiJXe+aX7HzItBwXWx9sgimTqhebDTFnB+jrXbPqvbQigjh7pHkXKeFdvU+NHI7Lrc2+ld4k559GmfmzpnKi377NRSUz8
            vDtX6dVMoAYN+hUvnSrroDd/9YYNdWsYfb3QojWMGIiQp3/9fnCYXRkcvDiszz5tFLib759O4uINAEgyjxjXKAk+gVUI33Z1kS+X
            VlneoInnm7EVKbzeAalKPdGszWh7atREWKNvuz8Q+78J00j/VIwcNxyMCZqNcXpXH1t8FKP3a/Jb+qN6sVps31jkdgifiVXA1Glm
            ahV9SkjsaitugqJaCKTltQ437H+PikWRXSxThSh8UK+SqZ62TiTUsWqG/YPukIdYA71GoFWBh7iItSIewWtGsfuXpMY9IIz7NJbR
            zg4lprzsnm+oxwA7E4YrxgmDSX2Y7JNIddZqoJZzUBtHMYNc7qzdsq5g+XGh4YOhXLrvZ0djXqGISiBQ8rlam5mtYtaAeSyf07AD
            nkGCqwuWIwDn5+/Hr16OWXFyS1+dBhuwM4lQPO2K6cHT4C5TxkhuZZ2N9fCrfpgcGsXOxQd7sOtHgUvTLAcQznGTAJ1Xv5kbHutO
            2CJ+d6M6yRJiGmJl/E2ZGCoy2PbXEN4TGjr4TPzGFuMHxtlUp0qI516U5B6KiXB/a7oi6ADaHf92roHNvBRvyiLD0sOpLjilFN+u
            e9aEXwn1K504EhEUI1ROESLh7dlwMz9G7w+j+oRxmDA0AexrUzWgtMSNeorM9lIGveoFzIbx5gv4bhYJNKV1PGBqUYkb9rAXmyO5
            joZwKMEO6mI6kXNEnFXYZmjh3RZhT8zrzfGkP/9dIjB0mMU0V9jx15djQzoFNBkkl6T9bvU/2DI8c7xSisKA7Fcaz3I29hCIZiNm
            ZtTFLRIWHL1XcTTr/SU+gzzVw+WX/rsxc5O1CBfUiZtyJ9rjgciv1a5mSy/Dae9sAVB4C5P9SKn7a5TvbXWQ9ei9EBk3kH5a6cMw
            DQYLKoZIhvcNAQkQAxwCARAwCwYJYIZIAWUDBAEFBCjx5g5mDo5CWJyHMKJV//p/v24tL5oOp8HVylDl4Mr54CIT/XM9HsPMMEwG
            CSqGSIb3DQEHATAdBglghkgBZQMEASoEEBund76AvG3fPvwLVTg7greAIOVz54L2YTgueIIKwtLhMolh1pJENqVNYk44fnjF5nL+
            """);

        // Generated with:
        // openssl cms -encrypt -binary -in content-512.txt -outform DER -out mlkem-512-with-ukm.der -aes128-wrap -recip cert-512.pem -recip_kdf HKDF-SHA256 -recip_ukm 4d4c2d4b454d2d3531323a4d4c2d4b454d2d353132
        internal static byte[] MLKem512WithUserKeyingMaterial => field ??= Convert.FromBase64String(
            """
            MIIELwYJKoZIhvcNAQcDoIIEIDCCBBwCAQMxggPHpIIDwwYLKoZIhvcNAQkQDQMwggOyAgEAMDowIjENMAsGA1UEChMESUVURjER
            MA8GA1UEAxMITEFNUFMgV0cCFBWf/m8i/VzELFJN9v1eKNDeOPNPMAsGCWCGSAFlAwQEAQSCAwD8A1Lk784jQx0XgnwrowlASEDn
            W62kbZ03OysmWlb7gaPeMSbLAJtgKrM5FUwC39n4y27FTFNJJuzPVjzcGC4G0nuJ/mqgX7YJDgCFVE5Ykp0yh50EsMWYt4i+/vAM
            efkYZk5XRYlfCPOdnzlmpFqh6ZgIl71s1JYbURUhQJOnezN7Memtw65wVK7th8OH1Bu6/UDNIYM0NQmIT0u1JChgE6zF/RYuGNrk
            kJGGqLVZKuU68qyxsnk3KM5J3Dc9TFupubksQHcoqSEAXMyH0q+ME7VC4kyFV0jeQZ/u1aTEWEc0axjHA0h6Hx6KY9bY0PEjToVK
            h0a9nYUEPg5Vuy/jxscHhKEfjDit4e/TIJf4JWizY6Nkzq8e3gM20gL1fOuwOmFkBOOg8zHYCJB3b04gDrONbZkVNC0a+t5j+ay7
            eUoZD5cj8H3ZMAtVA7IZyduvPMXnVfnpioIKH8zse2F9uO2rfugGRK3yaadG7T+2gnX57NP5JnFs8US9FQf9LUzSUx/DBvnef6hf
            PntHnQsHatoBgDBDv4YkeOor+amvNEG6kZDUCbORuZPTbYOEqC4XOYBna+GsY9LZfeS+E1epGUXq2Jt0B+vQfY0aSFHSlu+/qOFJ
            WNrmugIndnuTq5eDyGA8LtzI6PSDpLdxLcnxAFHyrQf1EWVe2mShYum3pm8QBYEIiyZZ6/YSjR9g0bm/af7Htku9CmxbRDIIjUKd
            T/tLPbia6vqierv/+gjaTkGi570YOEppHm5YBv8fo7JU0BpMt4Vg9NKTWIlv9EQ99CmA+mgfQEhNr4mFqLEC/qheQSAwOxyyzyrq
            ZQqlG6drn8mXZc4pSkxqb8I7K2QxVqu6QylPTlzy4jwNsiS4zPNhub7td4H2VZOzvO1xGjkt9UYwgzsNq7k/VtGRNAKoOTQ7L2Y8
            wJLJ+l6f6oL5c69we4dfcAA21HBlWEFpPn7cXczT7iC6BK+PIbLKfVLrOuD0EA4X4jo7lSSNoB5kCbPT2q6AC483h0NroytLQ08w
            DQYLKoZIhvcNAQkQAxwCARCgFwQVTUwtS0VNLTUxMjpNTC1LRU0tNTEyMAsGCWCGSAFlAwQBBQQoTONo3+aVivJDY9mMpIxk/YU6
            RVsJp2kKy4JV+t6227mvUHK5VOevjDBMBgkqhkiG9w0BBwEwHQYJYIZIAWUDBAEqBBD1CMUrf6zgNJSUU7j12z6kgCDzTI54b75X
            nfcipl9gyjqmo9EYn3/Yz76Tf4tm3ZSJuQ==
            """);

        internal static byte[] MLKem768Content => field ??= "Hello World ML-KEM-768"u8.ToArray();

        internal static byte[] MLKem768UserKeyingMaterial => field ??= "ML-KEM-768:ML-KEM-768"u8.ToArray();

        // Generated with:
        // openssl cms -encrypt -binary -in content-768.txt -outform DER -out mlkem-768-without-ukm.der -aes256-wrap -recip cert-768.pem -recip_kdf HKDF-SHA256
        internal static byte[] MLKem768WithoutUserKeyingMaterial => field ??= Convert.FromBase64String(
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
            jQGY6kEyPuoLBGkzUu5M+0hnjRA=
            """);

        // Derived from MLKem768WithoutUserKeyingMaterial with KEMRecipientInfo.version changed from 0 to 1.
        internal static byte[] MLKem768InvalidVersion => field ??= Convert.FromBase64String(
            """
            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
            jQGY6kEyPuoLBGkzUu5M+0hnjRA=
            """);

        // Derived from MLKem768WithUserKeyingMaterial because the OpenSSL CLI does not accept empty -recip_ukm.
        internal static byte[] MLKem768WithEmptyUserKeyingMaterial => field ??= Convert.FromBase64String(
            """
            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
            v7XNtc+X1xd9Fvx7IyOpOrdeOCCC0MEj
            """);

        // Generated with:
        // openssl cms -encrypt -binary -in content-768.txt -outform DER -out mlkem-768-with-ukm.der -aes256-wrap -recip cert-768.pem -recip_kdf HKDF-SHA256 -recip_ukm 4d4c2d4b454d2d3736383a4d4c2d4b454d2d373638
        internal static byte[] MLKem768WithUserKeyingMaterial => field ??= Convert.FromBase64String(
            """
            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
            """);

        internal static byte[] MLKem1024Content => field ??= "Hello World ML-KEM-1024"u8.ToArray();

        internal static byte[] MLKem1024UserKeyingMaterial => field ??= "ML-KEM-1024:ML-KEM-1024"u8.ToArray();

        // Generated with:
        // openssl cms -encrypt -binary -in content-1024.txt -outform DER -out mlkem-1024-without-ukm.der -aes256-wrap -recip cert-1024.pem -recip_kdf HKDF-SHA256
        internal static byte[] MLKem1024WithoutUserKeyingMaterial => field ??= Convert.FromBase64String(
            """
            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
            """);

        // Generated with:
        // openssl cms -encrypt -binary -in content-1024.txt -outform DER -out mlkem-1024-with-ukm.der -aes256-wrap -recip cert-1024.pem -recip_kdf HKDF-SHA256 -recip_ukm 4d4c2d4b454d2d313032343a4d4c2d4b454d2d31303234
        internal static byte[] MLKem1024WithUserKeyingMaterial => field ??= Convert.FromBase64String(
            """
            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
            hfE=
            """);
    }
}
