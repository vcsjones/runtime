// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Formats.Asn1;
using System.IO;

namespace System.Security.Cryptography.X509Certificates
{
    public static partial class X509CertificateLoader
    {
        public static partial X509Certificate2 LoadCertificate(ReadOnlySpan<byte> data)
        {
            if (data.IsEmpty ||
                !AndroidCertificatePal.TryReadX509(data, out ICertificatePal? cert))
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            return new X509Certificate2(cert);
        }

        public static partial X509Certificate2 LoadCertificateFromFile(string path)
        {
            ArgumentException.ThrowIfNullOrEmpty(path);

            using (FileStream stream = File.OpenRead(path))
            {
                int length = (int)long.Min(int.MaxValue, stream.Length);
                byte[] buf = CryptoPool.Rent(length);

                try
                {
                    stream.ReadAtLeast(buf, length);
                    return LoadCertificate(buf.AsSpan(0, length));
                }
                finally
                {
                    CryptoPool.Return(buf, length);
                }
            }
        }

        private static partial X509Certificate2 FromCertAndKey(CertAndKey certAndKey, ImportState importState)
        {
            AndroidCertificatePal pal = (AndroidCertificatePal)certAndKey.Cert!;

            if (certAndKey.Key != null)
            {
                pal.SetPrivateKey(AndroidPkcs12Reader.GetPrivateKey(certAndKey.Key));
                certAndKey.Key.Dispose();
            }

            return new X509Certificate2(pal);
        }

        private static partial AsymmetricAlgorithm? CreateKey(string algorithm)
        {
            return algorithm switch
            {
                Oids.Rsa or Oids.RsaPss => new RSAImplementation.RSAAndroid(),
                Oids.EcPublicKey or Oids.EcDiffieHellman => new ECDsaImplementation.ECDsaAndroid(),
                Oids.Dsa => new DSAImplementation.DSAAndroid(),
                _ => null,
            };
        }

        private static partial ICertificatePalCore LoadX509Der(ReadOnlyMemory<byte> data)
        {
            ReadOnlySpan<byte> span = data.Span;

            AsnValueReader reader = new AsnValueReader(span, AsnEncodingRules.DER);
            reader.ReadSequence();
            reader.ThrowIfNotEmpty();

            if (!AndroidCertificatePal.TryReadX509(span, out ICertificatePal? cert))
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            return cert;
        }
    }
}
