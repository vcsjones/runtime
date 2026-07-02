// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

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
    }
}
