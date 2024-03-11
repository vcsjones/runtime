// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Runtime.InteropServices;
using Internal.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography.X509Certificates
{
    public static partial class X509CertificateLoader
    {
        public static partial X509Certificate2 LoadCertificate(ReadOnlySpan<byte> data)
        {
            unsafe
            {
                fixed (byte* dataPtr = data)
                {
                    Interop.Crypt32.DATA_BLOB blob = new Interop.Crypt32.DATA_BLOB(
                        (IntPtr)dataPtr,
                        (uint)data.Length);

                    return LoadCertificate(
                        Interop.Crypt32.CertQueryObjectType.CERT_QUERY_OBJECT_BLOB,
                        &blob);
                }
            }
        }

        public static partial X509Certificate2 LoadCertificateFromFile(string path)
        {
            ArgumentNullException.ThrowIfNull(path);

            unsafe
            {
                fixed (char* pathPtr = path)
                {
                    return LoadCertificate(
                        Interop.Crypt32.CertQueryObjectType.CERT_QUERY_OBJECT_FILE,
                        pathPtr);
                }
            }
        }

        public static partial X509Certificate2Collection LoadPkcs12Collection(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<char> password,
            X509KeyStorageFlags keyStorageFlags,
            Pkcs12LoaderLimits? loaderLimits)
        {
            throw new Exception();
        }

        public static partial X509Certificate2 LoadPkcs12FromFile(
            string path,
            ReadOnlySpan<char> password,
            X509KeyStorageFlags keyStorageFlags,
            Pkcs12LoaderLimits? loaderLimits)
        {
            ArgumentNullException.ThrowIfNull(path);

            throw new Exception();
        }

        public static partial X509Certificate2Collection LoadPkcs12CollectionFromFile(
            string path,
            ReadOnlySpan<char> password,
            X509KeyStorageFlags keyStorageFlags,
            Pkcs12LoaderLimits? loaderLimits)
        {
            ArgumentNullException.ThrowIfNull(path);

            throw new Exception();
        }

        private static unsafe X509Certificate2 LoadCertificate(
            Interop.Crypt32.CertQueryObjectType objectType,
            void* pvObject)
        {
            Debug.Assert(objectType != 0);
            Debug.Assert(pvObject != (void*)0);

            const Interop.Crypt32.ContentType ContentType =
                Interop.Crypt32.ContentType.CERT_QUERY_CONTENT_CERT;
            const Interop.Crypt32.ExpectedContentTypeFlags ExpectedContentType =
                Interop.Crypt32.ExpectedContentTypeFlags.CERT_QUERY_CONTENT_FLAG_CERT;

            bool loaded = Interop.Crypt32.CryptQueryObject(
                objectType,
                pvObject,
                ExpectedContentType,
                Interop.Crypt32.ExpectedFormatTypeFlags.CERT_QUERY_FORMAT_FLAG_ALL,
                dwFlags: 0,
                pdwMsgAndCertEncodingType: IntPtr.Zero,
                out Interop.Crypt32.ContentType actualType,
                pdwFormatType: IntPtr.Zero,
                phCertStore: IntPtr.Zero,
                phMsg: IntPtr.Zero,
                out SafeCertContextHandle singleContext);

            if (!loaded)
            {
                singleContext.Dispose();
                throw Marshal.GetHRForLastWin32Error().ToCryptographicException();
            }

            // Since contentType is an input filter, actualType should not be possible to disagree.
            //
            // Since contentType is only CERT, singleContext should either be valid, or the
            // function should have returned false.
            if (actualType != ContentType || singleContext.IsInvalid)
            {
                singleContext.Dispose();
                throw new CryptographicException();
            }

            CertificatePal pal = new CertificatePal(singleContext, deleteKeyContainer: false);
            return new X509Certificate2(pal);
        }
    }
}
