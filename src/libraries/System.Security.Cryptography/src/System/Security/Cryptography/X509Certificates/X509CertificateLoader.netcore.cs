// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Diagnostics;

namespace System.Security.Cryptography.X509Certificates
{
    public static partial class X509CertificateLoader
    {
        public static partial X509Certificate2 LoadCertificate(byte[] data)
        {
            ThrowIfNull(data);

            return LoadCertificate(new ReadOnlySpan<byte>(data));
        }

        public static partial X509Certificate2 LoadCertificate(ReadOnlySpan<byte> data)
        {
            if (data.IsEmpty)
            {
                ThrowWithHResult(SR.Cryptography_Der_Invalid_Encoding, CRYPT_E_BAD_DECODE);
            }

            ICertificatePal pal = LoadCertificatePal(data);
            Debug.Assert(pal is not null);
            return new X509Certificate2(pal);
        }

        public static partial X509Certificate2 LoadCertificateFromFile(string path)
        {
            ArgumentException.ThrowIfNullOrEmpty(path);

            ICertificatePal pal = LoadCertificatePalFromFile(path);
            Debug.Assert(pal is not null);
            return new X509Certificate2(pal);
        }

        private static partial ICertificatePal LoadCertificatePal(ReadOnlySpan<byte> data);
        private static partial ICertificatePal LoadCertificatePalFromFile(string path);

        internal static ICertificatePal LoadPkcs12Pal(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<char> password,
            X509KeyStorageFlags keyStorageFlags,
            Pkcs12LoaderLimits loaderLimits)
        {
            Debug.Assert(loaderLimits is not null);

            unsafe
            {
                fixed (byte* pinned = data)
                {
                    using (PointerMemoryManager<byte> manager = new(pinned, data.Length))
                    {
                        return LoadPkcs12(
                            manager.Memory,
                            password,
                            keyStorageFlags,
                            loaderLimits).GetPal();
                    }
                }
            }
        }

        internal static ICertificatePal LoadPkcs12PalFromFile(
            string path,
            ReadOnlySpan<char> password,
            X509KeyStorageFlags keyStorageFlags,
            Pkcs12LoaderLimits? loaderLimits)
        {
            ThrowIfNullOrEmpty(path);

            return LoadFromFile(
                path,
                password,
                keyStorageFlags,
                loaderLimits ?? Pkcs12LoaderLimits.Defaults,
                LoadPkcs12).GetPal();
        }

        private readonly partial struct Pkcs12Return
        {
            private readonly ICertificatePal? _pal;

            internal Pkcs12Return(ICertificatePal pal)
            {
                _pal = pal;
            }

            internal ICertificatePal GetPal()
            {
                Debug.Assert(_pal is not null);
                return _pal;
            }

            internal partial bool HasValue() => _pal is not null;

            internal partial X509Certificate2 ToCertificate()
            {
                Debug.Assert(_pal is not null);

                return new X509Certificate2(_pal);
            }
        }
    }
}
