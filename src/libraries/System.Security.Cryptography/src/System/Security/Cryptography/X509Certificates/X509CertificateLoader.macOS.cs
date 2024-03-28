// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Security.Cryptography.Apple;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography.X509Certificates
{
    public static partial class X509CertificateLoader
    {
        public static partial X509Certificate2 LoadCertificate(ReadOnlySpan<byte> data)
        {
            return new X509Certificate2(LoadX509Der(data));
        }

        public static partial X509Certificate2 LoadCertificateFromFile(string path)
        {
            ArgumentException.ThrowIfNullOrEmpty(path);

            return LoadFromFile(path, default, default, default!, (memory, _, _, _) => LoadCertificate(memory.Span));
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
            return LoadX509Der(data.Span);
        }

        private static AppleCertificatePal LoadX509Der(ReadOnlySpan<byte> data)
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
