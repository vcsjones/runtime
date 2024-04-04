// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;

namespace System.Security.Cryptography.X509Certificates
{
    public static partial class X509CertificateLoader
    {
        static partial void LoadCertificateCore(byte[] data, ref X509Certificate2? earlyReturn)
        {
            X509ContentType contentType = X509Certificate2.GetCertContentType(data);

            if (contentType != X509ContentType.Cert)
            {
                ThrowWithHResult(SR.Cryptography_Der_Invalid_Encoding, CRYPT_E_BAD_DECODE);
            }

            earlyReturn = new X509Certificate2(data);
        }

        public static partial X509Certificate2 LoadCertificate(ReadOnlySpan<byte> data)
        {
            if (data.IsEmpty)
            {
                ThrowWithHResult(SR.Cryptography_Der_Invalid_Encoding, CRYPT_E_BAD_DECODE);
            }

            byte[] rented = CryptoPool.Rent(data.Length);

            try
            {
                data.CopyTo(rented);

                X509Certificate2? ret = null;
                LoadCertificateCore(rented, ref ret);
                Debug.Assert(ret is not null);

                return ret;
            }
            finally
            {
                CryptoPool.Return(rented, data.Length);
            }
        }

        public static partial X509Certificate2 LoadCertificateFromFile(string path)
        {
            X509ContentType contentType = X509Certificate2.GetCertContentType(path);

            if (contentType != X509ContentType.Cert)
            {
                ThrowWithHResult(SR.Cryptography_Der_Invalid_Encoding, CRYPT_E_BAD_DECODE);
            }

            return new X509Certificate2(path);
        }
    }
}
