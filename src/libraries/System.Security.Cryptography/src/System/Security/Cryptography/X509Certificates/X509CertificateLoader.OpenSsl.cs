// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography.X509Certificates
{
    public static partial class X509CertificateLoader
    {
        public static partial X509Certificate2 LoadCertificate(ReadOnlySpan<byte> data)
        {
            ICertificatePal? pal;

            if (OpenSslX509CertificateReader.TryReadX509Der(data, out pal) ||
                OpenSslX509CertificateReader.TryReadX509Pem(data, out pal))
            {
                return new X509Certificate2(pal);
            }

            throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
        }

        public static partial X509Certificate2 LoadCertificateFromFile(string path)
        {
            ArgumentException.ThrowIfNullOrEmpty(path);

            ICertificatePal? pal;

            using (SafeBioHandle fileBio = Interop.Crypto.BioNewFile(path, "rb"))
            {
                Interop.Crypto.CheckValidOpenSslHandle(fileBio);

                int bioPosition = Interop.Crypto.BioTell(fileBio);

                if (!OpenSslX509CertificateReader.TryReadX509Der(fileBio, out pal))
                {
                    Interop.Crypto.BioSeek(fileBio, bioPosition);

                    if (!OpenSslX509CertificateReader.TryReadX509Pem(fileBio, out pal))
                    {
                        throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                    }
                }
            }

            Debug.Assert(pal is not null);
            return new X509Certificate2(pal);
        }

        private static partial X509Certificate2 FromCertAndKey(CertAndKey certAndKey)
        {
            OpenSslX509CertificateReader pal = (OpenSslX509CertificateReader)certAndKey.Cert!;

            if (certAndKey.Key is not null)
            {
                pal.SetPrivateKey(OpenSslPkcs12Reader.GetPrivateKey(certAndKey.Key));
                certAndKey.Key.Dispose();
            }

            return new X509Certificate2(pal);
        }

        private static partial AsymmetricAlgorithm? CreateKey(string algorithm)
        {
            return algorithm switch
            {
                Oids.Rsa or Oids.RsaPss => new RSAOpenSsl(),
                Oids.EcPublicKey or Oids.EcDiffieHellman => new ECDiffieHellmanOpenSsl(),
                Oids.Dsa => new DSAOpenSsl(),
                _ => null,
            };
        }

        private static partial ICertificatePalCore LoadX509Der(ReadOnlyMemory<byte> data)
        {
            if (OpenSslX509CertificateReader.TryReadX509Der(data.Span, out ICertificatePal? ret))
            {
                return ret;
            }

            throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
        }
    }
}
