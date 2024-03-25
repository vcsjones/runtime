// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Diagnostics;
using System.Formats.Asn1;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Reflection;
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
            ArgumentException.ThrowIfNullOrEmpty(path);

            if (ReferenceEquals(loaderLimits, Pkcs12LoaderLimits.DangerousNoLimits))
            {
                X509Certificate2? earlyReturn = null;

                LoadPkcs12NoLimits(path, password, keyStorageFlags, ref earlyReturn);

                if (earlyReturn is not null)
                {
                    return earlyReturn;
                }
            }

            return LoadFromFile(
                path,
                password,
                keyStorageFlags,
                loaderLimits ?? Pkcs12LoaderLimits.Defaults,
                LoadPkcs12);
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
                new ReadOnlyMemory<byte>(data),
                password,
                keyStorageFlags,
                loaderLimits ?? Pkcs12LoaderLimits.Defaults);
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
            ArgumentNullException.ThrowIfNull(path);

            if (ReferenceEquals(loaderLimits, Pkcs12LoaderLimits.DangerousNoLimits))
            {
                X509Certificate2Collection? coll = null;

                LoadPkcs12NoLimits(path, password, keyStorageFlags, ref coll);

                if (coll is not null)
                {
                    return coll;
                }
            }

            return LoadFromFile(
                path,
                password,
                keyStorageFlags,
                loaderLimits ?? Pkcs12LoaderLimits.Defaults,
                LoadPkcs12Collection);
        }

        private delegate T LoadFromFileFunc<T>(
            ReadOnlyMemory<byte> data,
            ReadOnlySpan<char> password,
            X509KeyStorageFlags keyStorageFlags,
            Pkcs12LoaderLimits loaderLimits);

        private static T LoadFromFile<T>(
            string path,
            ReadOnlySpan<char> password,
            X509KeyStorageFlags keyStorageFlags,
            Pkcs12LoaderLimits loaderLimits,
            LoadFromFileFunc<T> loader)
        {
            (byte[]? rented, int length, MemoryMappedFile? mapped) = ReadAllBytesIfBerSequence(path);

            if (rented is not null)
            {
                Debug.Assert(mapped is null);

                try
                {
                    return loader(
                        new ReadOnlyMemory<byte>(rented, 0, length),
                        password,
                        keyStorageFlags,
                        loaderLimits);
                }
                finally
                {
                    CryptoPool.Return(rented, length);
                }
            }
            else
            {
                Debug.Assert(mapped is not null);

                using (mapped)
                using (MemoryMappedViewAccessor accessor = mapped.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read))
                {
                    unsafe
                    {
                        byte* pointer = null;

                        try
                        {
                            accessor.SafeMemoryMappedViewHandle.AcquirePointer(ref pointer);

                            using (PointerMemoryManager<byte> manager = new(pointer, length))
                            {
                                return loader(
                                    manager.Memory,
                                    password,
                                    keyStorageFlags,
                                    loaderLimits);
                            }
                        }
                        finally
                        {
                            if (pointer != null)
                            {
                                accessor.SafeMemoryMappedViewHandle.ReleasePointer();
                            }
                        }
                    }
                }
            }
        }

        // TODO: Get this made into a public method.
        private static readonly TryReadLength s_tryReadLength = (TryReadLength)typeof(AsnDecoder).GetMethod(
            nameof(TryReadLength), BindingFlags.Static | BindingFlags.NonPublic)!.CreateDelegate(typeof(TryReadLength));

        private delegate bool TryReadLength(
            ReadOnlySpan<byte> source,
            AsnEncodingRules ruleSet,
            out int? length,
            out int bytesRead);

        private static (byte[]?, int, MemoryMappedFile?) ReadAllBytesIfBerSequence(string path)
        {
            // The expected header in a PFX is 30 82 XX XX, but since it's BER-encoded
            // it could be up to 30 FE 00 00 00 .. XX YY ZZ AA and still be within the
            // bounds of what we can load into an array. 30 FE would be followed by 0x7E bytes,
            // so we need 0x81 total bytes for a tag and length using a maximal BER encoding.
            Span<byte> earlyBuf = stackalloc byte[0x81];

            try
            {
                using (FileStream stream = File.OpenRead(path))
                {
                    int read = stream.ReadAtLeast(earlyBuf, 2);

                    if (earlyBuf[0] != 0x30 || earlyBuf[1] is 0 or 1)
                    {
                        throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding)
                        {
                            HResult = CRYPT_E_BAD_DECODE,
                        };
                    }

                    int totalLength;

                    if (earlyBuf[1] < 0x80)
                    {
                        // The two bytes we already read, plus the interpreted length
                        totalLength = earlyBuf[1] + 2;
                    }
                    else if (earlyBuf[1] == 0x80)
                    {
                        // indeterminate length
                        long streamLength = stream.Length;

                        if (streamLength < 1_048_576)
                        {
                            totalLength = (int)streamLength;
                        }
                        else
                        {
                            totalLength = -1;
                        }
                    }
                    else
                    {
                        int lengthLength = earlyBuf[1] - 0x80;
                        int toRead = lengthLength - read;

                        if (toRead > 0)
                        {
                            int localRead = stream.ReadAtLeast(earlyBuf.Slice(read), toRead);
                            read += localRead;
                        }

                        ReadOnlySpan<byte> lengthPart = earlyBuf.Slice(1, read - 1);

                        if (!s_tryReadLength(lengthPart, AsnEncodingRules.BER, out int? decoded, out int decodedLength))
                        {
                            throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding)
                            {
                                HResult = CRYPT_E_BAD_DECODE,
                            };
                        }

                        Debug.Assert(decoded.HasValue);

                        // The interpreted value, the bytes involved in the length (which includes earlyBuf[1]),
                        // and the tag (earlyBuf[0])
                        totalLength = decoded.GetValueOrDefault() + decodedLength + 1;
                    }

                    if (totalLength >= 0)
                    {
                        byte[] rented = CryptoPool.Rent(totalLength);
                        earlyBuf.Slice(0, read).CopyTo(rented);

                        stream.ReadExactly(rented.AsSpan(read, totalLength - read));
                        return (rented, totalLength, null);
                    }

                    MemoryMappedFile mapped = MemoryMappedFile.CreateFromFile(
                        stream,
                        mapName: null,
                        capacity: stream.Length,
                        MemoryMappedFileAccess.Read,
                        HandleInheritability.None,
                        leaveOpen: false);

                    return (null, (int)long.Min(int.MaxValue, stream.Length), mapped);
                }
            }
            catch (IOException e)
            {
                throw new CryptographicException(SR.Arg_CryptographyException, e);
            }
            catch (UnauthorizedAccessException e)
            {
                throw new CryptographicException(SR.Arg_CryptographyException, e);
            }
        }
    }
}
