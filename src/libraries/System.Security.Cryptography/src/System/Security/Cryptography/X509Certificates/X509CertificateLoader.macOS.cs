// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Formats.Asn1;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Security.Cryptography.Apple;
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

            return new X509Certificate2(LoadX509(data));
        }

        public static partial X509Certificate2 LoadCertificateFromFile(string path)
        {
            ArgumentException.ThrowIfNullOrEmpty(path);

            using (FileStream stream = File.OpenRead(path))
            {
                int length = (int)long.Min(int.MaxValue, stream.Length);

                if (length > MemoryMappedFileCutoff)
                {
                    MemoryMappedFile mapped = MemoryMappedFile.CreateFromFile(
                        stream,
                        mapName: null,
                        capacity: stream.Length,
                        MemoryMappedFileAccess.Read,
                        HandleInheritability.None,
                        leaveOpen: false);

                    using (mapped)
                    using (MemoryMappedViewAccessor accessor = mapped.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read))
                    {
                        unsafe
                        {
                            byte* pointer = null;

                            try
                            {
                                accessor.SafeMemoryMappedViewHandle.AcquirePointer(ref pointer);

                                ReadOnlySpan<byte> data = new(pointer, length);
                                return LoadCertificate(data);
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
                else
                {
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
        }

        static partial void InitializeImportState(ref ImportState importState, X509KeyStorageFlags keyStorageFlags)
        {
            bool exportable = (keyStorageFlags & X509KeyStorageFlags.Exportable) == X509KeyStorageFlags.Exportable;

            bool persist =
                (keyStorageFlags & X509KeyStorageFlags.PersistKeySet) == X509KeyStorageFlags.PersistKeySet;

            SafeKeychainHandle keychain = persist
                ? Interop.AppleCrypto.SecKeychainCopyDefault()
                : Interop.AppleCrypto.CreateTemporaryKeychain();

            importState.Exportable = exportable;
            importState.Persisted = persist;
            importState.Keychain = keychain;
        }

        private static partial X509Certificate2 FromCertAndKey(CertAndKey certAndKey, ImportState importState)
        {
            AppleCertificatePal pal = (AppleCertificatePal)certAndKey.Cert!;
            SafeSecKeyRefHandle? key = null;

            if (certAndKey.Key is not null)
            {
                key = ApplePkcs12Reader.GetPrivateKey(certAndKey.Key);
                certAndKey.Key.Dispose();
            }

            if (key is not null || importState.Persisted)
            {
                if (key is not null && !importState.Exportable)
                {
                    AppleCertificatePal newPal = AppleCertificatePal.ImportPkcs12NonExportable(
                        pal,
                        key,
                        SafePasswordHandle.InvalidHandle,
                        importState.Keychain);

                    pal.Dispose();
                    pal = newPal;
                }
                else
                {
                    AppleCertificatePal? identity = pal.MoveToKeychain(importState.Keychain, key);

                    if (identity is not null)
                    {
                        pal.Dispose();
                        pal = identity;
                    }
                }
            }

            return new X509Certificate2(pal);
        }

        private static partial AsymmetricAlgorithm? CreateKey(string algorithm)
        {
            return algorithm switch
            {
                Oids.Rsa or Oids.RsaPss => new RSAImplementation.RSASecurityTransforms(),
                Oids.EcPublicKey or Oids.EcDiffieHellman => new ECDsaImplementation.ECDsaSecurityTransforms(),
                Oids.Dsa => new DSAImplementation.DSASecurityTransforms(),
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
            SafeSecCertificateHandle certHandle = Interop.AppleCrypto.X509ImportCertificate(
                data,
                X509ContentType.Cert,
                SafePasswordHandle.InvalidHandle,
                SafeTemporaryKeychainHandle.InvalidHandle,
                exportable: true,
                out SafeSecIdentityHandle identityHandle);

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

        private partial struct ImportState
        {
            internal bool Exportable;
            internal bool Persisted;
            internal SafeKeychainHandle Keychain;

            partial void DisposeCore()
            {
                Keychain?.Dispose();
                this = default;
            }
        }
    }
}
