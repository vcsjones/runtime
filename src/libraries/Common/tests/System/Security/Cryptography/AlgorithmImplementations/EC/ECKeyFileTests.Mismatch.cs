// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.Tests
{
    public abstract partial class ECKeyFileTests<T>
    {
        [Fact]
        public void Mismatch_ReadWriteEc256NamedECPrivateKeyPublicKey()
        {
            // The Q in this key falls on the curve, but G x D != Q.
            const string base64 = @"
MHcCAQEEIHChLC2xaEXtVv9oz8IaRys/BNfWhRv2NJ8tfVs0UrOKoAoGCCqGSM49AwEHoUQDQgAE
rZsBkBjHlngjE2f3bN0Jil7wEE/V1O4Py5WLjhP6TSnGBIG3xpZ3Kc2iXHA31di60AOVC1K8HVpi
vFKrvGIT9A==";

            ReadAndVerifyECPrivateKey(
                base64,
                EccTestData.GetNistP256ReferenceKey());
        }

        [Fact]
        public void Mismatch_ReadWriteEc256NamedECPrivateKey_PublicKeyNotOnCurve()
        {
            // The Q in this key is bogus, it does not fall anywhere on the curve.
            const string base64 = @"
MHcCAQEEIHChLC2xaEXtVv9oz8IaRys/BNfWhRv2NJ8tfVs0UrOKoAoGCCqGSM49AwEHoUQDQgAE
gQGqqqqqqqqqqvaabivT2IaRoyYtIsuk92Ner/JmgKjYoSumHVmSNfZ9nLTVjxeD08pD548KWrqq
qqqqqqqqqg==";

            ReadAndVerifyECPrivateKey(
                base64,
                EccTestData.GetNistP256ReferenceKey(),
                isSupported: PlatformDetection.IsOSX);
        }

        [Fact]
        public void Mismatch_ReadWriteEc256ExplicitPrimeECPrivateKey_PublicKeyNotOnCurve()
        {
            // The Q in this key is bogus, it does not fall anywhere on the curve.
            const string base64 = @"
MIIBaAIBAQQgcKEsLbFoRe1W/2jPwhpHKz8E19aFG/Y0ny19WzRSs4qggfowgfcCAQEwLAYHKoZI
zj0BAQIhAP////8AAAABAAAAAAAAAAAAAAAA////////////////MFsEIP////8AAAABAAAAAAAA
AAAAAAAA///////////////8BCBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVAMSd
NgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li
/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA//////////+85vqtpxeehPO5
ysL8YyVRAgEBoUQDQgAEgQGqqqqqqqqqqvaabivT2IaRoyYtIsuk92Ner/JmgKjYoSumHVmSNfZ9
nLTVjxeD08pD548KWrqqqqqqqqqqqg==";

            ReadAndVerifyECPrivateKey(
                base64,
                EccTestData.GetNistP256ReferenceKeyExplicit(),
                isSupported: false);
        }

        [Fact]
        public void Mismatch_ReadWriteEc256ExplicitPrimeECPrivateKey()
        {
            // The Q in this key falls on the curve, but G x D != Q.
            const string base64 = @"
MIIBaAIBAQQgcKEsLbFoRe1W/2jPwhpHKz8E19aFG/Y0ny19WzRSs4qggfowgfcCAQEwLAYHKoZI
zj0BAQIhAP////8AAAABAAAAAAAAAAAAAAAA////////////////MFsEIP////8AAAABAAAAAAAA
AAAAAAAA///////////////8BCBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVAMSd
NgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li
/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA//////////+85vqtpxeehPO5
ysL8YyVRAgEBoUQDQgAErZsBkBjHlngjE2f3bN0Jil7wEE/V1O4Py5WLjhP6TSnGBIG3xpZ3Kc2i
XHA31di60AOVC1K8HVpivFKrvGIT9A==";

            ReadAndVerifyECPrivateKey(
                base64,
                EccTestData.GetNistP256ReferenceKeyExplicit(),
                SupportsExplicitCurves);
        }

        [Fact]
        public void Mismatch_ReadWriteC2pnb163v1ECPrivateKey_PublicKeyNotOnCurve()
        {
            // The Q in this key is bogus, it does not fall anywhere on the curve.
            ReadAndVerifyECPrivateKey(
                @"
MIIBBwIBAQQVAPTSShQHEi9EWWe+HZPACTplNnmGoIG6MIG3AgEBMCUGByqGSM49AQIwGgICAKMG
CSqGSM49AQIDAzAJAgEBAgECAgEIMEQEFQclRrVDUjSkIuB4lnX0MsiUNd5SQgQUyVF9BtUkDTz/
OMdLILbNTW+d1NkDFQDSwPsVdghg3vHu9NaW5naHVhUXVAQrBAevaZiVRhA9eTKfzD10iA8zu+gD
ywHsIyEbWWat6h0/h/fqWEiu8LfKnwIVBAAAAAAAAAAAAAHmD8iCHMdNrq/BAgECoS4DLAAEqqqq
qqqqqqpoiOkb1pJXdJQjIkiqBCcIMPehAJrWcKiN6aqqqqqqqqqq",
                EccTestData.C2pnb163v1Key1Explicit,
                isSupported: false);
        }

        [Fact]
        public void Mismatch_ReadWriteC2pnb163v1ECPrivateKey()
        {
            // The Q in this key falls on the curve, but G x D != Q.
            ReadAndVerifyECPrivateKey(
                @"
MIIBBwIBAQQVAPTSShQHEi9EWWe+HZPACTplNnmGoIG6MIG3AgEBMCUGByqGSM49AQIwGgICAKMG
CSqGSM49AQIDAzAJAgEBAgECAgEIMEQEFQclRrVDUjSkIuB4lnX0MsiUNd5SQgQUyVF9BtUkDTz/
OMdLILbNTW+d1NkDFQDSwPsVdghg3vHu9NaW5naHVhUXVAQrBAevaZiVRhA9eTKfzD10iA8zu+gD
ywHsIyEbWWat6h0/h/fqWEiu8LfKnwIVBAAAAAAAAAAAAAHmD8iCHMdNrq/BAgECoS4DLAAEB1FS
6W2rmMiwVAwmdFWKDYfwlGvSB9L+a4lyZyi8ZTWMTr+GJ9E1+4qH",
                EccTestData.C2pnb163v1Key1Explicit,
                SupportsC2pnb163v1);
        }

        protected void ReadAndVerifyECPrivateKey(string base64, ECParameters ecParameters, bool isSupported = true)
        {
            byte[] derEcPrivateKey = Convert.FromBase64String(base64);

            using T key = CreateKey();

            if (isSupported)
            {
                ImportECPrivateKey(key, derEcPrivateKey, out _);
                ExerciseAgainstKey(key, ecParameters);
            }
            else
            {
                Exception ex = Assert.ThrowsAny<Exception>(() => ImportECPrivateKey(key, derEcPrivateKey, out _));
                Assert.True(ex is PlatformNotSupportedException || ex is CryptographicException);
            }
        }

        protected abstract void ExerciseAgainstKey(T key, ECParameters otherKey);
    }
}
