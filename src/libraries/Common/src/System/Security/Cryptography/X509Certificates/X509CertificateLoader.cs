// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.IO;
using System.Runtime.Versioning;

namespace System.Security.Cryptography.X509Certificates
{
    [UnsupportedOSPlatform("browser")]
    public static partial class X509CertificateLoader
    {
        /// <summary>
        ///   Loads a single X.509 certificate from <paramref name="data"/>, in either the PEM
        ///   or DER encoding.
        /// </summary>
        /// <param name="data">The data to load.</param>
        /// <returns>
        ///   The certificate loaded from <paramref name="data"/>.
        /// </returns>
        /// <exception cref="CryptographicException">
        ///   The data did not load as a valid X.509 certificate.
        /// </exception>
        /// <remarks>
        ///   This method only loads plain certificates, which are identified as
        ///   <see cref="X509ContentType.Cert" /> by <see cref="X509Certificate2.GetCertContentType(byte[])"/>
        /// </remarks>
        /// <seealso cref="X509Certificate2.GetCertContentType(string)"/>
        public static partial X509Certificate2 LoadCertificate(ReadOnlySpan<byte> data);

        /// <summary>
        ///   Loads a single X.509 certificate from <paramref name="data"/>, in either the PEM
        ///   or DER encoding.
        /// </summary>
        /// <param name="data">The data to load.</param>
        /// <returns>
        ///   The certificate loaded from <paramref name="data"/>.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="data"/> is <see langword="null" />.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   The data did not load as a valid X.509 certificate.
        /// </exception>
        /// <remarks>
        ///   This method only loads plain certificates, which are identified as
        ///   <see cref="X509ContentType.Cert" /> by <see cref="X509Certificate2.GetCertContentType(byte[])"/>
        /// </remarks>
        /// <seealso cref="X509Certificate2.GetCertContentType(string)"/>
        public static X509Certificate2 LoadCertificate(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);

            return LoadCertificate(new ReadOnlySpan<byte>(data));
        }

        /// <summary>
        ///   Loads a single X.509 certificate (in either the PEM or DER encoding)
        ///   from the specified file.
        /// </summary>
        /// <param name="path">The path of the file to open.</param>
        /// <returns>
        ///   The loaded certificate.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="path"/> is <see langword="null" />.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   The data did not load as a valid X.509 certificate.
        /// </exception>
        /// <exception cref="IOException">
        ///   An error occurred while loading the specified file.
        /// </exception>
        /// <remarks>
        ///   This method only loads plain certificates, which are identified as
        ///   <see cref="X509ContentType.Cert" /> by <see cref="X509Certificate2.GetCertContentType(string)"/>
        /// </remarks>
        /// <seealso cref="X509Certificate2.GetCertContentType(string)"/>
        public static partial X509Certificate2 LoadCertificateFromFile(string path);

        /// <summary>
        ///   Loads the provided data as a PKCS#12 PFX and extracts a certificate.
        /// </summary>
        /// <param name="data">The data to load.</param>
        /// <param name="password">The password to decrypt the contents of the PFX.</param>
        /// <param name="keyStorageFlags">
        ///   A bitwise combination of the enumeration values that control where and how to
        ///   import the private key associated with the returned certificate.
        /// </param>
        /// <param name="loaderLimits">
        ///   Limits to apply when loading the PFX.  A <see langword="null" /> value, the default,
        ///   is equivalent to <see cref="Pkcs12LoaderLimits.Defaults"/>.
        /// </param>
        /// <returns>The loaded certificate.</returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="data"/> is <see langword="null" />.
        /// </exception>
        /// <exception cref="Pkcs12LoadLimitExceededException">
        ///   The PKCS#12/PFX violated one or more constraints of <paramref name="loaderLimits"/>.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred while loading the PKCS#12/PFX.
        /// </exception>
        /// <remarks>
        ///   A PKCS#12/PFX can contain multiple certificates.
        ///   Using the ordering that the certificates appear in the results of
        ///   <see cref="LoadPkcs12Collection(ReadOnlySpan{byte},ReadOnlySpan{char},X509KeyStorageFlags,Pkcs12LoaderLimits?)" />,
        ///   this method returns the first
        ///   certificate where <see cref="X509Certificate2.HasPrivateKey" /> is
        ///   <see langword="true" />.
        ///   If no certificates have associated private keys, then the first
        ///   certificate is returned.
        ///   If the PKCS#12/PFX contains no certificates, a
        ///   <see cref="CryptographicException" /> is thrown.
        /// </remarks>
        public static X509Certificate2 LoadPkcs12(
            byte[] data,
            string? password,
            X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet,
            Pkcs12LoaderLimits? loaderLimits = null)
        {
            ArgumentNullException.ThrowIfNull(data);

            return LoadPkcs12(
                new ReadOnlyMemory<byte>(data),
                password.AsSpan(),
                keyStorageFlags,
                loaderLimits ?? Pkcs12LoaderLimits.Defaults);
        }

        /// <summary>
        ///   Loads the provided data as a PKCS#12 PFX and extracts a certificate.
        /// </summary>
        /// <param name="data">The data to load.</param>
        /// <param name="password">The password to decrypt the contents of the PFX.</param>
        /// <param name="keyStorageFlags">
        ///   A bitwise combination of the enumeration values that control where and how to
        ///   import the private key associated with the returned certificate.
        /// </param>
        /// <param name="loaderLimits">
        ///   Limits to apply when loading the PFX.  A <see langword="null" /> value, the default,
        ///   is equivalent to <see cref="Pkcs12LoaderLimits.Defaults"/>.
        /// </param>
        /// <returns>The loaded certificate.</returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="data"/> is <see langword="null" />.
        /// </exception>
        /// <exception cref="Pkcs12LoadLimitExceededException">
        ///   The PKCS#12/PFX violated one or more constraints of <paramref name="loaderLimits"/>.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred while loading the PKCS#12/PFX.
        /// </exception>
        /// <remarks>
        ///   A PKCS#12/PFX can contain multiple certificates.
        ///   Using the ordering that the certificates appear in the results of
        ///   <see cref="LoadPkcs12Collection(byte[],string?, X509KeyStorageFlags,Pkcs12LoaderLimits?)" />,
        ///   this method returns the first
        ///   certificate where <see cref="X509Certificate2.HasPrivateKey" /> is
        ///   <see langword="true" />.
        ///   If no certificates have associated private keys, then the first
        ///   certificate is returned.
        ///   If the PKCS#12/PFX contains no certificates, a
        ///   <see cref="CryptographicException" /> is thrown.
        /// </remarks>
        public static X509Certificate2 LoadPkcs12(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<char> password,
            X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet,
            Pkcs12LoaderLimits? loaderLimits = null)
        {
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
                            loaderLimits ?? Pkcs12LoaderLimits.Defaults);
                    }
                }
            }
        }

        /// <summary>
        ///   Opens the specified file, reads the contents as a PKCS#12 PFX and extracts a certificate.
        /// </summary>
        /// <param name="path">The path of the file to open.</param>
        /// <returns>
        ///   The loaded certificate.
        /// </returns>
        /// <param name="password">The password to decrypt the contents of the PFX.</param>
        /// <param name="keyStorageFlags">
        ///   A bitwise combination of the enumeration values that control where and how to
        ///   import the private key associated with the returned certificate.
        /// </param>
        /// <param name="loaderLimits">
        ///   Limits to apply when loading the PFX.  A <see langword="null" /> value, the default,
        ///   is equivalent to <see cref="Pkcs12LoaderLimits.Defaults"/>.
        /// </param>
        /// <returns>The loaded certificate.</returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="path"/> is <see langword="null" />.
        /// </exception>
        /// <exception cref="Pkcs12LoadLimitExceededException">
        ///   The PKCS#12/PFX violated one or more constraints of <paramref name="loaderLimits"/>.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred while loading the PKCS#12/PFX.
        /// </exception>
        /// <exception cref="IOException">
        ///   An error occurred while loading the specified file.
        /// </exception>
        /// <remarks>
        ///   A PKCS#12/PFX can contain multiple certificates.
        ///   Using the ordering that the certificates appear in the results of
        ///   <see cref="LoadPkcs12CollectionFromFile(string,string?, X509KeyStorageFlags,Pkcs12LoaderLimits?)" />,
        ///   this method returns the first
        ///   certificate where <see cref="X509Certificate2.HasPrivateKey" /> is
        ///   <see langword="true" />.
        ///   If no certificates have associated private keys, then the first
        ///   certificate is returned.
        ///   If the PKCS#12/PFX contains no certificates, a
        ///   <see cref="CryptographicException" /> is thrown.
        /// </remarks>
        public static X509Certificate2 LoadPkcs12FromFile(
            string path,
            string? password,
            X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet,
            Pkcs12LoaderLimits? loaderLimits = null)
        {
            return LoadPkcs12FromFile(
                path,
                password.AsSpan(),
                keyStorageFlags,
                loaderLimits);
        }

        /// <summary>
        ///   Opens the specified file, reads the contents as a PKCS#12 PFX and extracts a certificate.
        /// </summary>
        /// <param name="path">The path of the file to open.</param>
        /// <returns>
        ///   The loaded certificate.
        /// </returns>
        /// <param name="password">The password to decrypt the contents of the PFX.</param>
        /// <param name="keyStorageFlags">
        ///   A bitwise combination of the enumeration values that control where and how to
        ///   import the private key associated with the returned certificate.
        /// </param>
        /// <param name="loaderLimits">
        ///   Limits to apply when loading the PFX.  A <see langword="null" /> value, the default,
        ///   is equivalent to <see cref="Pkcs12LoaderLimits.Defaults"/>.
        /// </param>
        /// <returns>The loaded certificate.</returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="path"/> is <see langword="null" />.
        /// </exception>
        /// <exception cref="Pkcs12LoadLimitExceededException">
        ///   The PKCS#12/PFX violated one or more constraints of <paramref name="loaderLimits"/>.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred while loading the PKCS#12/PFX.
        /// </exception>
        /// <exception cref="IOException">
        ///   An error occurred while loading the specified file.
        /// </exception>
        /// <remarks>
        ///   A PKCS#12/PFX can contain multiple certificates.
        ///   Using the ordering that the certificates appear in the results of
        ///   <see cref="LoadPkcs12CollectionFromFile(string, ReadOnlySpan{char}, X509KeyStorageFlags,Pkcs12LoaderLimits?)" />,
        ///   this method returns the first
        ///   certificate where <see cref="X509Certificate2.HasPrivateKey" /> is
        ///   <see langword="true" />.
        ///   If no certificates have associated private keys, then the first
        ///   certificate is returned.
        ///   If the PKCS#12/PFX contains no certificates, a
        ///   <see cref="CryptographicException" /> is thrown.
        /// </remarks>
        public static X509Certificate2 LoadPkcs12FromFile(
            string path,
            ReadOnlySpan<char> password,
            X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet,
            Pkcs12LoaderLimits? loaderLimits = null)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        ///   Loads the provided data as a PKCS#12 PFX and returns a collection of
        ///   all of the certificates therein.
        /// </summary>
        /// <param name="data">The data to load.</param>
        /// <param name="password">The password to decrypt the contents of the PFX.</param>
        /// <param name="keyStorageFlags">
        ///   A bitwise combination of the enumeration values that control where and how to
        ///   import the private key associated with the returned certificate.
        /// </param>
        /// <param name="loaderLimits">
        ///   Limits to apply when loading the PFX.  A <see langword="null" /> value, the default,
        ///   is equivalent to <see cref="Pkcs12LoaderLimits.Defaults"/>.
        /// </param>
        /// <returns>A collection of the certificates loaded from the input.</returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="data"/> is <see langword="null" />.
        /// </exception>
        /// <exception cref="Pkcs12LoadLimitExceededException">
        ///   The PKCS#12/PFX violated one or more constraints of <paramref name="loaderLimits"/>.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred while loading the PKCS#12/PFX.
        /// </exception>
        public static X509Certificate2Collection LoadPkcs12Collection(
            byte[] data,
            string? password,
            X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet,
            Pkcs12LoaderLimits? loaderLimits = null)
        {
            ArgumentNullException.ThrowIfNull(data);

            return LoadPkcs12Collection(
                new ReadOnlySpan<byte>(data),
                password.AsSpan(),
                keyStorageFlags,
                loaderLimits);
        }

        /// <summary>
        ///   Loads the provided data as a PKCS#12 PFX and returns a collection of
        ///   all of the certificates therein.
        /// </summary>
        /// <param name="data">The data to load.</param>
        /// <param name="password">The password to decrypt the contents of the PFX.</param>
        /// <param name="keyStorageFlags">
        ///   A bitwise combination of the enumeration values that control where and how to
        ///   import the private key associated with the returned certificate.
        /// </param>
        /// <param name="loaderLimits">
        ///   Limits to apply when loading the PFX.  A <see langword="null" /> value, the default,
        ///   is equivalent to <see cref="Pkcs12LoaderLimits.Defaults"/>.
        /// </param>
        /// <returns>A collection of the certificates loaded from the input.</returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="data"/> is <see langword="null" />.
        /// </exception>
        /// <exception cref="Pkcs12LoadLimitExceededException">
        ///   The PKCS#12/PFX violated one or more constraints of <paramref name="loaderLimits"/>.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred while loading the PKCS#12/PFX.
        /// </exception>
        public static X509Certificate2Collection LoadPkcs12Collection(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<char> password,
            X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet,
            Pkcs12LoaderLimits? loaderLimits = null)
        {
            unsafe
            {
                fixed (byte* pinned = data)
                {
                    using (PointerMemoryManager<byte> manager = new(pinned, data.Length))
                    {
                        return LoadPkcs12Collection(
                            manager.Memory,
                            password,
                            keyStorageFlags,
                            loaderLimits ?? Pkcs12LoaderLimits.Defaults);
                    }
                }
            }
        }

        /// <summary>
        ///   Opens the specified file, reads the contents as a PKCS#12 PFX and extracts a certificate.
        ///   Loads the provided data as a PKCS#12 PFX and returns a collection of
        ///   all of the certificates therein.
        /// </summary>
        /// <param name="path">The path of the file to open.</param>
        /// <returns>
        ///   The loaded certificate.
        /// </returns>
        /// <param name="password">The password to decrypt the contents of the PFX.</param>
        /// <param name="keyStorageFlags">
        ///   A bitwise combination of the enumeration values that control where and how to
        ///   import the private key associated with the returned certificate.
        /// </param>
        /// <param name="loaderLimits">
        ///   Limits to apply when loading the PFX.  A <see langword="null" /> value, the default,
        ///   is equivalent to <see cref="Pkcs12LoaderLimits.Defaults"/>.
        /// </param>
        /// <returns>The loaded certificate.</returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="path"/> is <see langword="null" />.
        /// </exception>
        /// <exception cref="Pkcs12LoadLimitExceededException">
        ///   The PKCS#12/PFX violated one or more constraints of <paramref name="loaderLimits"/>.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred while loading the PKCS#12/PFX.
        /// </exception>
        /// <exception cref="IOException">
        ///   An error occurred while loading the specified file.
        /// </exception>
        public static X509Certificate2Collection LoadPkcs12CollectionFromFile(
            string path,
            string? password,
            X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet,
            Pkcs12LoaderLimits? loaderLimits = null)
        {
            return LoadPkcs12CollectionFromFile(
                path,
                password.AsSpan(),
                keyStorageFlags,
                loaderLimits);
        }

        /// <summary>
        ///   Opens the specified file, reads the contents as a PKCS#12 PFX and extracts a certificate.
        ///   Loads the provided data as a PKCS#12 PFX and returns a collection of
        ///   all of the certificates therein.
        /// </summary>
        /// <param name="path">The path of the file to open.</param>
        /// <returns>
        ///   The loaded certificate.
        /// </returns>
        /// <param name="password">The password to decrypt the contents of the PFX.</param>
        /// <param name="keyStorageFlags">
        ///   A bitwise combination of the enumeration values that control where and how to
        ///   import the private key associated with the returned certificate.
        /// </param>
        /// <param name="loaderLimits">
        ///   Limits to apply when loading the PFX.  A <see langword="null" /> value, the default,
        ///   is equivalent to <see cref="Pkcs12LoaderLimits.Defaults"/>.
        /// </param>
        /// <returns>The loaded certificate.</returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="path"/> is <see langword="null" />.
        /// </exception>
        /// <exception cref="Pkcs12LoadLimitExceededException">
        ///   The PKCS#12/PFX violated one or more constraints of <paramref name="loaderLimits"/>.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred while loading the PKCS#12/PFX.
        /// </exception>
        /// <exception cref="IOException">
        ///   An error occurred while loading the specified file.
        /// </exception>
        public static X509Certificate2Collection LoadPkcs12CollectionFromFile(
            string path,
            ReadOnlySpan<char> password,
            X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet,
            Pkcs12LoaderLimits? loaderLimits = null)
        {
            throw new NotImplementedException();
        }
    }
}
