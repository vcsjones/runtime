// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Security.Cryptography.X509Certificates
{
    public static partial class X509CertificateLoader
    {
        public static partial X509Certificate2 LoadCertificate(ReadOnlySpan<byte> data)
        {
            throw new PlatformNotSupportedException(SR.SystemSecurityCryptographyX509Certificates_PlatformNotSupported);
        }

        public static partial X509Certificate2 LoadCertificateFromFile(string path)
        {
            throw new PlatformNotSupportedException(SR.SystemSecurityCryptographyX509Certificates_PlatformNotSupported);
        }

        private static partial X509Certificate2 LoadPkcs12(
            ref BagState bagState,
            ReadOnlySpan<char> password,
            X509KeyStorageFlags keyStorageFlags)
        {
            throw new PlatformNotSupportedException(SR.SystemSecurityCryptographyX509Certificates_PlatformNotSupported);
        }

        private static partial X509Certificate2Collection LoadPkcs12Collection(
            ref BagState bagState,
            ReadOnlySpan<char> password,
            X509KeyStorageFlags keyStorageFlags)
        {
            throw new PlatformNotSupportedException(SR.SystemSecurityCryptographyX509Certificates_PlatformNotSupported);
        }
    }
}
