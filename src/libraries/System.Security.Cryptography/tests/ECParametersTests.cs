// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using Xunit;

namespace System.Security.Cryptography.Tests
{
    public static class ECParametersTests
    {
        [Theory]
        [InlineData("secP160r1")]
        [InlineData("secP160r2")]
        public static void Validate_NamedCurveOrderLargerThanField_AllowsPrivateKeyLongerThanPublicKey(string curveName)
        {
            ECParameters parameters = new ECParameters
            {
                Curve = ECCurve.CreateFromFriendlyName(curveName),
                Q =
                {
                    X = new byte[20],
                    Y = new byte[20],
                },
                D = new byte[21],
            };

            parameters.Validate();
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public static void Validate_NamedCurveWithEmptyPrivateKey_Throws(bool hasPublicKey)
        {
            ECParameters parameters = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = Array.Empty<byte>(),
            };

            if (hasPublicKey)
            {
                parameters.Q = new ECPoint
                {
                    X = new byte[32],
                    Y = new byte[32],
                };
            }

            Assert.Throws<CryptographicException>(() => parameters.Validate());
        }

        [Theory]
        [MemberData(nameof(Secp160r2ECPrivateKeys))]
        public static void ImportECPrivateKey_Secp160r2OrderLargerThanField_ParsesPublicKeyWithFieldWidth(
            string base64Key,
            string expectedXHex,
            string expectedYHex,
            string expectedDHex)
        {
            using CapturingECAlgorithm algorithm = new CapturingECAlgorithm();
            byte[] key = Convert.FromBase64String(base64Key);

            algorithm.ImportECPrivateKey(key, out int bytesRead);

            ECParameters parameters = algorithm.ImportedParameters;
            Assert.Equal(key.Length, bytesRead);
            Assert.Equal("1.3.132.0.30", parameters.Curve.Oid.Value);
            Assert.Equal(Convert.FromHexString(expectedXHex), parameters.Q.X);
            Assert.Equal(Convert.FromHexString(expectedYHex), parameters.Q.Y);
            Assert.Equal(Convert.FromHexString(expectedDHex), parameters.D);
            Assert.Equal(20, parameters.Q.X!.Length);
            Assert.Equal(20, parameters.Q.Y!.Length);
            Assert.Equal(21, parameters.D!.Length);
        }

        public static IEnumerable<object[]> Secp160r2ECPrivateKeys
        {
            get
            {
                yield return new object[]
                {
                    """
                    MFECAQEEFQCM0i5BxZVZ6fXCZhraFFQGEd+ilaAHBgUrgQQAHqEsAyoABCnyZW4j
                    7uW6ZMNcBn73nO9WTLgDhhlmjCX7ETXPJ+rL8Cs2Y/0Ub9I=
                    """,
                    "29F2656E23EEE5BA64C35C067EF79CEF564CB803",
                    "8619668C25FB1135CF27EACBF02B3663FD146FD2",
                    "008CD22E41C59559E9F5C2661ADA14540611DFA295",
                };

                // This key was constructed with D = 2^160. Generating one with the left-most byte as 01 has
                // a probability of about 2^-89, so instead we construct it.
                // The value is valid because secp160r2's order is greater than 2^160; Q was derived as D * G.
                yield return new object[]
                {
                    """
                    MFECAQEEFQEAAAAAAAAAAAAAAAAAAAAAAAAAAKAHBgUrgQQAHqEsAyoABHZCyDa5
                    sXKeYXMAvhZbtpoCriXpNrtsfH4jDbqYmGL53VQF/3lEF6Y=
                    """,
                    "7642C836B9B1729E617300BE165BB69A02AE25E9",
                    "36BB6C7C7E230DBA989862F9DD5405FF794417A6",
                    "010000000000000000000000000000000000000000",
                };
            }
        }

        private sealed class CapturingECAlgorithm : ECAlgorithm
        {
            internal ECParameters ImportedParameters { get; private set; }

            public override void ImportParameters(ECParameters parameters)
            {
                ImportedParameters = new ECParameters
                {
                    Curve = parameters.Curve,
                    Q =
                    {
                        X = parameters.Q.X is null ? null : (byte[])parameters.Q.X.Clone(),
                        Y = parameters.Q.Y is null ? null : (byte[])parameters.Q.Y.Clone(),
                    },
                    D = parameters.D is null ? null : (byte[])parameters.D.Clone(),
                };
            }
        }
    }
}
