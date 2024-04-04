// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Formats.Asn1;
using System.IO;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography.X509Certificates
{
    public static partial class X509CertificateLoader
    {
        public static partial X509Certificate2 LoadCertificate(ReadOnlySpan<byte> data)
        {
            if (data.IsEmpty)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            if (X509Certificate2.GetCertContentType(data) != X509ContentType.Cert)
            {

                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            return new X509Certificate2(LoadX509(data));
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
            AppleCertificatePal pal = (AppleCertificatePal)certAndKey.Cert!;

            if (certAndKey.Key is not null)
            {
                AppleCertificatePal newPal = AppleCertificatePal.ImportPkcs12(pal, certAndKey.Key);
                pal.Dispose();
                pal = newPal;
            }

            return new X509Certificate2(pal);
        }

        private static partial AsymmetricAlgorithm? CreateKey(string algorithm)
        {
            return algorithm switch
            {
                Oids.Rsa or Oids.RsaPss => new RSAImplementation.RSASecurityTransforms(),
                Oids.EcPublicKey or Oids.EcDiffieHellman => new ECDsaImplementation.ECDsaSecurityTransforms(),
                // There's no DSA support on iOS/tvOS.
                _ => null,
            };
        }

        private static partial ICertificatePalCore LoadX509Der(ReadOnlyMemory<byte> data)
        {
            ReadOnlySpan<byte> span = data.Span;

            AsnValueReader reader = new AsnValueReader(span, AsnEncodingRules.DER);
            reader.ReadSequence();
            reader.ThrowIfNotEmpty();

            return LoadX509(span);
        }

        private static AppleCertificatePal LoadX509(ReadOnlySpan<byte> data)
        {
            SafeSecIdentityHandle identityHandle;
            SafeSecCertificateHandle certHandle = Interop.AppleCrypto.X509ImportCertificate(
                data,
                X509ContentType.Cert,
                SafePasswordHandle.InvalidHandle,
                out identityHandle);

            if (identityHandle.IsInvalid)
            {
                identityHandle.Dispose();
                return new AppleCertificatePal(certHandle);
            }

            Debug.Fail("Non-PKCS12 import produced an identity handle");

            identityHandle.Dispose();
            certHandle.Dispose();
            throw new CryptographicException();
        }
    }
}
