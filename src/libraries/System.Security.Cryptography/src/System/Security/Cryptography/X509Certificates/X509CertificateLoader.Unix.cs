// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Security.Cryptography.X509Certificates
{
    public static partial class X509CertificateLoader
    {
        public static partial X509Certificate2 LoadCertificate(ReadOnlySpan<byte> data)
        {
            throw new Exception();
        }

        public static partial X509Certificate2 LoadCertificateFromFile(string path)
        {
            throw new Exception();
        }

        //public static partial X509Certificate2 LoadPkcs12(
        //    ReadOnlySpan<byte> data,
        //    ReadOnlySpan<char> password,
        //    X509KeyStorageFlags keyStorageFlags,
        //    Pkcs12LoaderLimits? loaderLimits)
        //{
        //    throw new Exception();
        //}

        public static partial X509Certificate2Collection LoadPkcs12Collection(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<char> password,
            X509KeyStorageFlags keyStorageFlags,
            Pkcs12LoaderLimits? loaderLimits)
        {
            throw new Exception();
        }
    }
}
