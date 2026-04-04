// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Test.Cryptography;

namespace System.Security.Cryptography.Tests
{
    public static class X25519DiffieHellmanTestData
    {
        // RFC 7748 Section 6.1 test vectors
        public const string AlicePrivateKeyHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
        public const string AlicePublicKeyHex = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
        public const string BobPrivateKeyHex = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
        public const string BobPublicKeyHex = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
        public const string SharedSecretHex = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

        public const string X25519Oid = "1.3.101.110";

        public const string EncryptedPrivateKeyPassword = "PLACEHOLDER";
        public static ReadOnlySpan<byte> EncryptedPrivateKeyPasswordBytes => "PLACEHOLDER"u8;

        // SPKI DER prefix for X25519: SEQUENCE { SEQUENCE { OID 1.3.101.110 } BIT STRING ... }
        private const string SpkiPrefix = "302a300506032b656e032100";

        // PKCS#8 DER prefix for X25519: SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.110 }, OCTET STRING { OCTET STRING ... } }
        private const string Pkcs8Prefix = "302e020100300506032b656e04220420";

        // Alice's SPKI
        public static readonly byte[] AliceSpki = (SpkiPrefix + AlicePublicKeyHex).HexToByteArray();

        // Alice's PKCS#8
        public static readonly byte[] AlicePkcs8 = (Pkcs8Prefix + AlicePrivateKeyHex).HexToByteArray();

        // Bob's SPKI
        public static readonly byte[] BobSpki = (SpkiPrefix + BobPublicKeyHex).HexToByteArray();

        // Bob's PKCS#8
        public static readonly byte[] BobPkcs8 = (Pkcs8Prefix + BobPrivateKeyHex).HexToByteArray();

        // Encrypted PKCS#8 for Alice's private key, password = "PLACEHOLDER", AES-128-CBC
        public static readonly byte[] AliceEncryptedPkcs8 =
            ("3081a3305f06092a864886f70d01050d3052303106092a864886f70d01050c" +
             "302404106a2d90cfd9a8f9644d4ea289a19758a602020800300c06082a8648" +
             "86f70d02090500301d0609608648016503040102041099bb649f99a8dc086f" +
             "3e3d4110fa0d4a04409bee7166f2dce53783315ddede6e0bd194f2deda3e22" +
             "94e092b1018cad6d2dc008ede619ad5159daede3b8e502719ac69743f5e582" +
             "b0671e2327d7341217d40c").HexToByteArray();

        // Alice's SPKI PEM
        public const string AliceSpkiPem =
            "-----BEGIN PUBLIC KEY-----\n" +
            "MCowBQYDK2VuAyEAhSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=\n" +
            "-----END PUBLIC KEY-----";
    }
}
