// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Security.Cryptography.Apple;
using System.Security.Cryptography.Asn1.Pkcs7;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography.X509Certificates
{
    internal sealed partial class AppleCertificatePal : ICertificatePal
    {
        private SafeKeychainHandle? _tempKeychain;

        public static ICertificatePal FromBlob(
            ReadOnlySpan<byte> rawData,
            SafePasswordHandle password,
            X509KeyStorageFlags keyStorageFlags)
        {
            Debug.Assert(password != null);

            X509ContentType contentType = X509Certificate2.GetCertContentType(rawData);

            if (contentType == X509ContentType.Pkcs7)
            {
                return CertificatePkcs7Loader.LoadPkcs7<AppleCertificatePal>(rawData, keyStorageFlags);
            }

            if (contentType == X509ContentType.Pkcs12)
            {
                if ((keyStorageFlags & X509KeyStorageFlags.EphemeralKeySet) == X509KeyStorageFlags.EphemeralKeySet)
                {
                    throw new PlatformNotSupportedException(SR.Cryptography_X509_NoEphemeralPfx);
                }

                bool exportable = (keyStorageFlags & X509KeyStorageFlags.Exportable) == X509KeyStorageFlags.Exportable;

                bool persist =
                    (keyStorageFlags & X509KeyStorageFlags.PersistKeySet) == X509KeyStorageFlags.PersistKeySet;

                SafeKeychainHandle keychain = persist
                    ? Interop.AppleCrypto.SecKeychainCopyDefault()
                    : Interop.AppleCrypto.CreateTemporaryKeychain();

                using (keychain)
                {
                    AppleCertificatePal ret = ImportPkcs12(rawData, password, exportable, keychain);
                    if (!persist)
                    {
                        // If we used temporary keychain we need to prevent deletion.
                        // on 10.15+ if keychain is unlinked, certain certificate operations may fail.
                        bool success = false;
                        keychain.DangerousAddRef(ref success);
                        if (success)
                        {
                            ret._tempKeychain = keychain;
                        }
                    }

                    return ret;
                }
            }

            SafeSecIdentityHandle identityHandle;
            SafeSecCertificateHandle certHandle = Interop.AppleCrypto.X509ImportCertificate(
                rawData,
                contentType,
                SafePasswordHandle.InvalidHandle,
                SafeTemporaryKeychainHandle.InvalidHandle,
                exportable: true,
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

        public void DisposeTempKeychain()
        {
            Interlocked.Exchange(ref _tempKeychain, null)?.Dispose();
        }

        internal unsafe byte[] ExportPkcs8(ReadOnlySpan<char> password)
        {
            Debug.Assert(_identityHandle != null);

            using (SafeSecKeyRefHandle key = Interop.AppleCrypto.X509GetPrivateKeyFromIdentity(_identityHandle))
            {
                return ExportPkcs8(key, password);
            }
        }

        internal static unsafe byte[] ExportPkcs8(SafeSecKeyRefHandle key, ReadOnlySpan<char> password)
        {
            using (SafeCFDataHandle data = Interop.AppleCrypto.SecKeyExportData(key, exportPrivate: true, password))
            {
                ReadOnlySpan<byte> systemExport = Interop.CoreFoundation.CFDataDangerousGetSpan(data);

                fixed (byte* ptr = systemExport)
                {
                    using (PointerMemoryManager<byte> manager = new PointerMemoryManager<byte>(ptr, systemExport.Length))
                    {
                        // Apple's PKCS8 export exports using PBES2, which Win7, Win8.1, and Apple all fail to
                        // understand in their PKCS12 readers, so re-encrypt using the Win7 PKCS12-PBE parameters.
                        //
                        // Since Apple only reliably exports keys with encrypted PKCS#8 there's not a
                        // "so export it plaintext and only encrypt it once" option.
                        AsnWriter writer = KeyFormatHelper.ReencryptPkcs8(
                            password,
                            manager.Memory,
                            password,
                            UnixExportProvider.s_windowsPbe);

                        return writer.Encode();
                    }
                }
            }
        }

        internal AppleCertificatePal? MoveToKeychain(SafeKeychainHandle keychain, SafeSecKeyRefHandle? privateKey)
        {
            SafeSecIdentityHandle? identity = Interop.AppleCrypto.X509MoveToKeychain(
                _certHandle,
                keychain,
                privateKey);

            if (identity != null)
            {
                return new AppleCertificatePal(identity);
            }

            return null;
        }
    }
}
