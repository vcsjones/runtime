// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Internal.Cryptography.Pal
{
    internal static class CertificateExtensionsCommon
    {
        private static readonly string[] s_RsaOids = new string[] { Oids.Rsa, Oids.RsaPss };
        private static readonly string[] s_DsaOids = new string[] { Oids.Dsa };
        private static readonly string[] s_EcDsaOids = new string[] { Oids.EcPublicKey };

        public static T GetPublicKey<T>(
            this X509Certificate2 certificate,
            Predicate<X509Certificate2> matchesConstraints = null)
            where T : AsymmetricAlgorithm
        {
            if (certificate == null)
                throw new ArgumentNullException(nameof(certificate));

            ReadOnlySpan<string> oidValues = GetExpectedOidValues<T>();
            PublicKey publicKey = certificate.PublicKey;
            Oid algorithmOid = publicKey.Oid;
            if (!oidValues.Contains(algorithmOid.Value))
                return null;

            if (matchesConstraints != null && !matchesConstraints(certificate))
                return null;

            byte[] rawEncodedKeyValue = publicKey.EncodedKeyValue.RawData;
            byte[] rawEncodedParameters = publicKey.EncodedParameters.RawData;
            return (T)(X509Pal.Instance.DecodePublicKey(algorithmOid, rawEncodedKeyValue, rawEncodedParameters, certificate.Pal));
        }

        public static T GetPrivateKey<T>(
            this X509Certificate2 certificate,
            Predicate<X509Certificate2> matchesConstraints = null)
            where T : AsymmetricAlgorithm
        {
            if (certificate == null)
                throw new ArgumentNullException(nameof(certificate));

            ReadOnlySpan<string> oidValues = GetExpectedOidValues<T>();
            if (!certificate.HasPrivateKey || !oidValues.Contains(certificate.PublicKey.Oid.Value))
                return null;

            if (matchesConstraints != null && !matchesConstraints(certificate))
                return null;

            if (typeof(T) == typeof(RSA))
                return (T)(object)certificate.Pal.GetRSAPrivateKey();

            if (typeof(T) == typeof(ECDsa))
                return (T)(object)certificate.Pal.GetECDsaPrivateKey();

            if (typeof(T) == typeof(DSA))
                return (T)(object)certificate.Pal.GetDSAPrivateKey();

            Debug.Fail($"Expected {nameof(GetExpectedOidValues)}() to have thrown before we got here.");
            throw new NotSupportedException(SR.NotSupported_KeyAlgorithm);
        }

        private static string[] GetExpectedOidValues<T>() where T : AsymmetricAlgorithm
        {
            if (typeof(T) == typeof(RSA))
                return s_RsaOids;
            if (typeof(T) == typeof(ECDsa))
                return s_EcDsaOids;
            if (typeof(T) == typeof(DSA))
                return s_DsaOids;
            throw new NotSupportedException(SR.NotSupported_KeyAlgorithm);
        }
    }
}
