// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Runtime.InteropServices;
using Internal.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography.X509Certificates
{
    internal sealed partial class CertificatePal : IDisposable, ICertificatePal
    {
        public bool HasPrivateKey
        {
            get
            {
                return _certContext.ContainsPrivateKey;
            }
        }

        public RSA? GetRSAPrivateKey()
        {
            return GetPrivateKey<RSA>(
                delegate (CspParameters csp)
                {
                    return new RSACryptoServiceProvider(csp);
                },
                delegate (CngKey cngKey)
                {
                    return new RSACng(cngKey, transferOwnership: true);
                }
            );
        }

        public DSA? GetDSAPrivateKey()
        {
            return GetPrivateKey<DSA>(
                delegate (CspParameters csp)
                {
                    return new DSACryptoServiceProvider(csp);
                },
                delegate (CngKey cngKey)
                {
                    return new DSACng(cngKey, transferOwnership: true);
                }
            );
        }

        public ECDsa? GetECDsaPrivateKey()
        {
            return GetPrivateKey<ECDsa>(
                delegate (CspParameters csp)
                {
                    throw new NotSupportedException(SR.NotSupported_ECDsa_Csp);
                },
                delegate (CngKey cngKey)
                {
                    return new ECDsaCng(cngKey, transferOwnership: true);
                }
            );
        }

        public ECDiffieHellman? GetECDiffieHellmanPrivateKey()
        {
            static ECDiffieHellmanCng? FromCngKey(CngKey cngKey)
            {
                if (cngKey.AlgorithmGroup == CngAlgorithmGroup.ECDiffieHellman)
                {
                    return new ECDiffieHellmanCng(cngKey, transferOwnership: true);
                }

                // We might be getting an ECDSA key here. CNG allows ECDH to be either ECDH or ECDSA, however if
                // the AlgorithmGroup is ECDSA, then it cannot be used for ECDH, even though both of them are ECC keys.
                return null;
            }

            return GetPrivateKey<ECDiffieHellman>(
                csp => throw new NotSupportedException(SR.NotSupported_ECDiffieHellman_Csp),
                FromCngKey
            );
        }

        public MLDsa? GetMLDsaPrivateKey()
        {
            return GetPrivateKey<MLDsa>(
                _ =>
                {
                    Debug.Fail("CryptoApi does not support ML-DSA.");
                    throw new PlatformNotSupportedException();
                },
                cngKey => new MLDsaCng(cngKey, transferOwnership: true)
            );
        }

        public MLKem? GetMLKemPrivateKey()
        {
            // MLKem is not supported on Windows.
            return null;
        }

        public SlhDsa? GetSlhDsaPrivateKey()
        {
            // SlhDsa is not supported on Windows.
            return null;
        }

        public ICertificatePal CopyWithPrivateKey(DSA dsa)
        {
            DSACng? dsaCng = dsa as DSACng;
            ICertificatePal? clone;

            if (dsaCng != null)
            {
                clone = CopyWithPersistedCngKey(dsaCng.Key);

                if (clone != null)
                {
                    return clone;
                }
            }

            DSACryptoServiceProvider? dsaCsp = dsa as DSACryptoServiceProvider;

            if (dsaCsp != null)
            {
                clone = CopyWithPersistedCapiKey(dsaCsp.CspKeyContainerInfo);

                if (clone != null)
                {
                    return clone;
                }
            }

            DSAParameters privateParameters = dsa.ExportParameters(true);

            using (PinAndClear.Track(privateParameters.X!))
            using (DSACng clonedKey = new DSACng())
            {
                clonedKey.ImportParameters(privateParameters);

                return CopyWithEphemeralKey(clonedKey.Key);
            }
        }

        public ICertificatePal CopyWithPrivateKey(ECDsa ecdsa)
        {
            ECDsaCng? ecdsaCng = ecdsa as ECDsaCng;

            if (ecdsaCng != null)
            {
                ICertificatePal? clone = CopyWithPersistedCngKey(ecdsaCng.Key);

                if (clone != null)
                {
                    return clone;
                }
            }

            ECParameters privateParameters = ecdsa.ExportParameters(true);

            using (PinAndClear.Track(privateParameters.D!))
            using (ECDsaCng clonedKey = new ECDsaCng())
            {
                clonedKey.ImportParameters(privateParameters);

                return CopyWithEphemeralKey(clonedKey.Key);
            }
        }

        public ICertificatePal CopyWithPrivateKey(ECDiffieHellman ecdh)
        {
            ECDiffieHellmanCng? ecdhCng = ecdh as ECDiffieHellmanCng;

            if (ecdhCng != null)
            {
                ICertificatePal? clone = CopyWithPersistedCngKey(ecdhCng.Key);

                if (clone != null)
                {
                    return clone;
                }
            }

            ECParameters privateParameters = ecdh.ExportParameters(true);

            using (PinAndClear.Track(privateParameters.D!))
            using (ECDiffieHellmanCng clonedKey = new ECDiffieHellmanCng())
            {
                clonedKey.ImportParameters(privateParameters);

                return CopyWithEphemeralKey(clonedKey.Key);
            }
        }

        public ICertificatePal CopyWithPrivateKey(MLDsa privateKey)
        {
            if (privateKey is MLDsaCng mldsaCng)
            {
                CngKey key = mldsaCng.KeyNoDuplicate;

                ICertificatePal? clone = CopyWithPersistedCngKey(key);

                if (clone != null)
                {
                    return clone;
                }
            }

            if (privateKey is MLDsaImplementation mldsaImplementation)
            {
                using (CngKey clonedKey = mldsaImplementation.CreateEphemeralCng())
                {
                    return CopyWithEphemeralKey(clonedKey);
                }
            }

            // MLDsaCng and third-party implementations can be copied by exporting the PKCS#8 and importing it into
            // a new MLDsaCng. An alternative to PKCS#8 would be to try the private seed and fall back to secret key,
            // but that potentially requires two calls and wouldn't allow implementations to do anything smarter internally.
            // Blobs may also be an option for MLDsaCng, but for now we will stick with PKCS#8.
            byte[] exportedPkcs8 = privateKey.ExportPkcs8PrivateKey();

            using (PinAndClear.Track(exportedPkcs8))
            using (MLDsaCng clonedKey = MLDsaCng.ImportPkcs8PrivateKey(exportedPkcs8, out _))
            {
                CngKey clonedCngKey = clonedKey.KeyNoDuplicate;

                if (clonedCngKey.AlgorithmGroup != CngAlgorithmGroup.MLDsa)
                {
                    Debug.Fail($"{nameof(MLDsaCng)} should only give ML-DSA keys.");
                    throw new CryptographicException();
                }

                return CopyWithEphemeralKey(clonedCngKey);
            }
        }

        public ICertificatePal CopyWithPrivateKey(MLKem privateKey)
        {
            throw new PlatformNotSupportedException(SR.Format(SR.Cryptography_AlgorithmNotSupported, nameof(MLKem)));
        }

        public ICertificatePal CopyWithPrivateKey(SlhDsa privateKey)
        {
            throw new PlatformNotSupportedException(SR.Format(SR.Cryptography_AlgorithmNotSupported, nameof(SlhDsa)));
        }

        public ICertificatePal CopyWithPrivateKey(RSA rsa)
        {
            RSACng? rsaCng = rsa as RSACng;
            ICertificatePal? clone;

            if (rsaCng != null)
            {
                clone = CopyWithPersistedCngKey(rsaCng.Key);

                if (clone != null)
                {
                    return clone;
                }
            }

            RSACryptoServiceProvider? rsaCsp = rsa as RSACryptoServiceProvider;

            if (rsaCsp != null)
            {
                clone = CopyWithPersistedCapiKey(rsaCsp.CspKeyContainerInfo);

                if (clone != null)
                {
                    return clone;
                }
            }

            RSAParameters privateParameters = rsa.ExportParameters(true);

            using (PinAndClear.Track(privateParameters.D!))
            using (PinAndClear.Track(privateParameters.P!))
            using (PinAndClear.Track(privateParameters.Q!))
            using (PinAndClear.Track(privateParameters.DP!))
            using (PinAndClear.Track(privateParameters.DQ!))
            using (PinAndClear.Track(privateParameters.InverseQ!))
            using (RSACng clonedKey = new RSACng())
            {
                clonedKey.ImportParameters(privateParameters);

                return CopyWithEphemeralKey(clonedKey.Key);
            }
        }

        private T? GetPrivateKey<T>(Func<CspParameters, T> createCsp, Func<CngKey, T?> createCng)
            where T : class, IDisposable
        {
            using (SafeCertContextHandle certContext = GetCertContext())
            {
                SafeNCryptKeyHandle? ncryptKey = TryAcquireCngPrivateKey(certContext, out CngKeyHandleOpenOptions cngHandleOptions);
                if (ncryptKey != null)
                {
                    CngKey cngKey = CngKey.OpenNoDuplicate(ncryptKey, cngHandleOptions);
                    T? result = createCng(cngKey);

                    // Dispose of cngKey if its ownership did not transfer to the underlying algorithm.
                    if (result is null)
                    {
                        cngKey.Dispose();
                    }

                    return result;
                }
            }

            CspParameters? cspParameters = GetPrivateKeyCsp();
            if (cspParameters == null)
                return null;

            if (cspParameters.ProviderType == 0)
            {
                // ProviderType being 0 signifies that this is actually a CNG key, not a CAPI key. Crypt32.dll stuffs the CNG Key Storage Provider
                // name into CRYPT_KEY_PROV_INFO->ProviderName, and the CNG key name into CRYPT_KEY_PROV_INFO->KeyContainerName.

                string keyStorageProvider = cspParameters.ProviderName!;
                string keyName = cspParameters.KeyContainerName!;
                CngKey cngKey = CngKey.Open(keyName, new CngProvider(keyStorageProvider));
                return createCng(cngKey);
            }
            else
            {
                // ProviderType being non-zero signifies that this is a CAPI key.
                // We never want to stomp over certificate private keys.
                cspParameters.Flags |= CspProviderFlags.UseExistingKey;
                return createCsp(cspParameters);
            }
        }

        private static SafeNCryptKeyHandle? TryAcquireCngPrivateKey(
            SafeCertContextHandle certificateContext,
            out CngKeyHandleOpenOptions handleOptions)
        {
            Debug.Assert(certificateContext != null);
            Debug.Assert(!certificateContext.IsClosed && !certificateContext.IsInvalid);

            IntPtr privateKeyPtr;

            // If the certificate has a key handle without a key prov info, return the
            // ephemeral key
            if (!certificateContext.HasPersistedPrivateKey)
            {
                int cbData = IntPtr.Size;

                if (Interop.Crypt32.CertGetCertificateContextProperty(
                    certificateContext,
                    Interop.Crypt32.CertContextPropId.CERT_NCRYPT_KEY_HANDLE_PROP_ID,
                    out privateKeyPtr,
                    ref cbData))
                {
                    handleOptions = CngKeyHandleOpenOptions.EphemeralKey;
                    return new SafeNCryptKeyHandle(privateKeyPtr, certificateContext);
                }
            }

            bool freeKey = true;
            SafeNCryptKeyHandle? privateKey = null;
            handleOptions = CngKeyHandleOpenOptions.None;
            try
            {
                int keySpec = 0;
                if (!Interop.crypt32.CryptAcquireCertificatePrivateKey(
                    certificateContext,
                    Interop.Crypt32.CryptAcquireCertificatePrivateKeyFlags.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
                    IntPtr.Zero,
                    out privateKey,
                    out keySpec,
                    out freeKey))
                {

                    // The documentation for CryptAcquireCertificatePrivateKey says that freeKey
                    // should already be false if "key acquisition fails", and it can be presumed
                    // that privateKey was set to 0.  But, just in case:
                    freeKey = false;
                    privateKey?.SetHandleAsInvalid();
                    return null;
                }

                // It is very unlikely that Windows will tell us !freeKey other than when reporting failure,
                // because we set neither CRYPT_ACQUIRE_CACHE_FLAG nor CRYPT_ACQUIRE_USE_PROV_INFO_FLAG, which are
                // currently the only two success situations documented. However, any !freeKey response means the
                // key's lifetime is tied to that of the certificate, so re-register the handle as a child handle
                // of the certificate.
                if (!freeKey && privateKey != null && !privateKey.IsInvalid)
                {
                    var newKeyHandle = new SafeNCryptKeyHandle(privateKey.DangerousGetHandle(), certificateContext);
                    privateKey.SetHandleAsInvalid();
                    privateKey = newKeyHandle;
                    freeKey = true;
                }

                return privateKey;
            }
            catch
            {
                // If we aren't supposed to free the key, and we're not returning it,
                // just tell the SafeHandle to not free itself.
                if (privateKey != null && !freeKey)
                {
                    privateKey.SetHandleAsInvalid();
                }

                throw;
            }
        }

        //
        // Returns the private key referenced by a store certificate. Note that despite the return type being declared "CspParameters",
        // the key can actually be a CNG key. To distinguish, examine the ProviderType property. If it is 0, this key is a CNG key with
        // the various properties of CspParameters being "repurposed" into storing CNG info.
        //
        // This is a behavior this method inherits directly from the Crypt32 CRYPT_KEY_PROV_INFO semantics.
        //
        // It would have been nice not to let this ugliness escape out of this helper method. But X509Certificate2.ToString() calls this
        // method too so we cannot just change it without breaking its output.
        //
        private CspParameters? GetPrivateKeyCsp()
        {
            int cbData = 0;
            if (!Interop.Crypt32.CertGetCertificateContextProperty(_certContext, Interop.Crypt32.CertContextPropId.CERT_KEY_PROV_INFO_PROP_ID, null, ref cbData))
            {
                int dwErrorCode = Marshal.GetLastPInvokeError();
                if (dwErrorCode == ErrorCode.CRYPT_E_NOT_FOUND)
                    return null;
                throw dwErrorCode.ToCryptographicException();
            }

            unsafe
            {
                byte[] privateKey = new byte[cbData];
                fixed (byte* pPrivateKey = privateKey)
                {
                    if (!Interop.Crypt32.CertGetCertificateContextProperty(_certContext, Interop.Crypt32.CertContextPropId.CERT_KEY_PROV_INFO_PROP_ID, privateKey, ref cbData))
                        throw Marshal.GetLastPInvokeError().ToCryptographicException();
                    Interop.Crypt32.CRYPT_KEY_PROV_INFO* pKeyProvInfo = (Interop.Crypt32.CRYPT_KEY_PROV_INFO*)pPrivateKey;

                    CspParameters cspParameters = new CspParameters();
                    cspParameters.ProviderName = Marshal.PtrToStringUni((IntPtr)(pKeyProvInfo->pwszProvName));
                    cspParameters.KeyContainerName = Marshal.PtrToStringUni((IntPtr)(pKeyProvInfo->pwszContainerName));
                    cspParameters.ProviderType = pKeyProvInfo->dwProvType;
                    cspParameters.KeyNumber = pKeyProvInfo->dwKeySpec;
                    cspParameters.Flags = (CspProviderFlags)((pKeyProvInfo->dwFlags & Interop.Crypt32.CryptAcquireContextFlags.CRYPT_MACHINE_KEYSET) == Interop.Crypt32.CryptAcquireContextFlags.CRYPT_MACHINE_KEYSET ? CspProviderFlags.UseMachineKeyStore : 0);
                    return cspParameters;
                }
            }
        }

        private unsafe CertificatePal? CopyWithPersistedCngKey(CngKey cngKey)
        {
            if (string.IsNullOrEmpty(cngKey.KeyName))
            {
                return null;
            }

            // Make a new pal from bytes.
            CertificatePal pal = (CertificatePal)FromBlob(RawData, SafePasswordHandle.InvalidHandle, X509KeyStorageFlags.PersistKeySet);

            CngProvider provider = cngKey.Provider!;
            string keyName = cngKey.KeyName;
            bool machineKey = cngKey.IsMachineKey;

            // CAPI RSA_SIGN keys won't open correctly under CNG without the key number being specified, so
            // check to see if we can figure out what key number it needs to re-open.
            int keySpec = GuessKeySpec(provider, keyName, machineKey, cngKey.AlgorithmGroup);

            Interop.Crypt32.CRYPT_KEY_PROV_INFO keyProvInfo = default;

            fixed (char* keyNamePtr = cngKey.KeyName)
            fixed (char* provNamePtr = cngKey.Provider!.Provider)
            {
                keyProvInfo.pwszContainerName = keyNamePtr;
                keyProvInfo.pwszProvName = provNamePtr;
                keyProvInfo.dwFlags = machineKey ? Interop.Crypt32.CryptAcquireContextFlags.CRYPT_MACHINE_KEYSET : 0;
                keyProvInfo.dwKeySpec = keySpec;

                if (!Interop.Crypt32.CertSetCertificateContextProperty(
                    pal._certContext,
                    Interop.Crypt32.CertContextPropId.CERT_KEY_PROV_INFO_PROP_ID,
                    Interop.Crypt32.CertSetPropertyFlags.None,
                    &keyProvInfo))
                {
                    Exception e = Marshal.GetLastPInvokeError().ToCryptographicException();
                    pal.Dispose();
                    throw e;
                }
            }

            return pal;
        }

        private static int GuessKeySpec(
            CngProvider provider,
            string keyName,
            bool machineKey,
            CngAlgorithmGroup? algorithmGroup)
        {
            if (provider == CngProvider.MicrosoftSoftwareKeyStorageProvider ||
                provider == CngProvider.MicrosoftSmartCardKeyStorageProvider)
            {
                // Well-known CNG providers, keySpec is 0.
                return 0;
            }

            try
            {
                CngKeyOpenOptions options = machineKey ? CngKeyOpenOptions.MachineKey : CngKeyOpenOptions.None;

                using (CngKey.Open(keyName, provider, options))
                {
                    // It opened with keySpec 0, so use keySpec 0.
                    return 0;
                }
            }
            catch (CryptographicException)
            {
                // While NTE_BAD_KEYSET is what we generally expect here for RSA, on Windows 7
                // PROV_DSS produces NTE_BAD_PROV_TYPE, and PROV_DSS_DH produces NTE_NO_KEY.
                //
                // So we'll just try the CAPI fallback for any error code, and see what happens.

                CspParameters cspParameters = new CspParameters
                {
                    ProviderName = provider.Provider,
                    KeyContainerName = keyName,
                    Flags = CspProviderFlags.UseExistingKey,
                    KeyNumber = (int)KeyNumber.Signature,
                };

                if (machineKey)
                {
                    cspParameters.Flags |= CspProviderFlags.UseMachineKeyStore;
                }

                int keySpec;

                if (TryGuessKeySpec(cspParameters, algorithmGroup, out keySpec))
                {
                    return keySpec;
                }

                throw;
            }
        }

        private static bool TryGuessKeySpec(
            CspParameters cspParameters,
            CngAlgorithmGroup? algorithmGroup,
            out int keySpec)
        {
            if (algorithmGroup == CngAlgorithmGroup.Rsa)
            {
                return TryGuessRsaKeySpec(cspParameters, out keySpec);
            }

            if (algorithmGroup == CngAlgorithmGroup.Dsa)
            {
                return TryGuessDsaKeySpec(cspParameters, out keySpec);
            }

            keySpec = 0;
            return false;
        }

        private static bool TryGuessRsaKeySpec(CspParameters cspParameters, out int keySpec)
        {
            // Try the AT_SIGNATURE spot in each of the 4 RSA provider type values,
            // ideally one of them will work.
            const int PROV_RSA_FULL = 1;
            const int PROV_RSA_SIG = 2;
            const int PROV_RSA_SCHANNEL = 12;
            const int PROV_RSA_AES = 24;

            // These are ordered in terms of perceived likeliness, given that the key
            // is AT_SIGNATURE.
            int[] provTypes =
            {
                PROV_RSA_FULL,
                PROV_RSA_AES,
                PROV_RSA_SCHANNEL,

                // Nothing should be PROV_RSA_SIG, but if everything else has failed,
                // just try this last thing.
                PROV_RSA_SIG,
            };

            foreach (int provType in provTypes)
            {
                cspParameters.ProviderType = provType;

                try
                {
                    using (new RSACryptoServiceProvider(cspParameters))
                    {
                        {
                            keySpec = cspParameters.KeyNumber;
                            return true;
                        }
                    }
                }
                catch (CryptographicException)
                {
                }
            }

            Debug.Fail("RSA key did not open with KeyNumber 0 or AT_SIGNATURE");
            keySpec = 0;
            return false;
        }

        private static bool TryGuessDsaKeySpec(CspParameters cspParameters, out int keySpec)
        {
            const int PROV_DSS = 3;
            const int PROV_DSS_DH = 13;

            int[] provTypes =
            {
                PROV_DSS_DH,
                PROV_DSS,
            };

            foreach (int provType in provTypes)
            {
                cspParameters.ProviderType = provType;

                try
                {
                    using (new DSACryptoServiceProvider(cspParameters))
                    {
                        {
                            keySpec = cspParameters.KeyNumber;
                            return true;
                        }
                    }
                }
                catch (CryptographicException)
                {
                }
            }

            Debug.Fail("DSA key did not open with KeyNumber 0 or AT_SIGNATURE");
            keySpec = 0;
            return false;
        }

        private unsafe CertificatePal? CopyWithPersistedCapiKey(CspKeyContainerInfo keyContainerInfo)
        {
            if (string.IsNullOrEmpty(keyContainerInfo.KeyContainerName))
            {
                return null;
            }

            // Make a new pal from bytes.
            CertificatePal pal = (CertificatePal)FromBlob(RawData, SafePasswordHandle.InvalidHandle, X509KeyStorageFlags.PersistKeySet);
            Interop.Crypt32.CRYPT_KEY_PROV_INFO keyProvInfo = default;

            fixed (char* keyName = keyContainerInfo.KeyContainerName)
            fixed (char* provName = keyContainerInfo.ProviderName)
            {
                keyProvInfo.pwszContainerName = keyName;
                keyProvInfo.pwszProvName = provName;
                keyProvInfo.dwFlags = keyContainerInfo.MachineKeyStore ? Interop.Crypt32.CryptAcquireContextFlags.CRYPT_MACHINE_KEYSET : 0;
                keyProvInfo.dwProvType = keyContainerInfo.ProviderType;
                keyProvInfo.dwKeySpec = (int)keyContainerInfo.KeyNumber;

                if (!Interop.Crypt32.CertSetCertificateContextProperty(
                    pal._certContext,
                    Interop.Crypt32.CertContextPropId.CERT_KEY_PROV_INFO_PROP_ID,
                    Interop.Crypt32.CertSetPropertyFlags.None,
                    &keyProvInfo))
                {
                    Exception e = Marshal.GetLastPInvokeError().ToCryptographicException();
                    pal.Dispose();
                    throw e;
                }
            }

            return pal;
        }

        private CertificatePal CopyWithEphemeralKey(CngKey cngKey)
        {
            Debug.Assert(string.IsNullOrEmpty(cngKey.KeyName));

            // Handle makes a copy of the handle.  This is required given that CertSetCertificateContextProperty accepts a SafeHandle
            // and transfers ownership of the handle to the certificate.  We can't transfer that ownership out of the cngKey, as it's
            // owned by the caller, so we make a copy (using Handle rather than HandleNoDuplicate).
            using (SafeNCryptKeyHandle handle = cngKey.Handle)
            {
                // Make a new pal from bytes.
                CertificatePal pal = (CertificatePal)FromBlob(RawData, SafePasswordHandle.InvalidHandle, X509KeyStorageFlags.PersistKeySet);
                try
                {
                    if (!Interop.Crypt32.CertSetCertificateContextProperty(
                        pal._certContext,
                        Interop.Crypt32.CertContextPropId.CERT_NCRYPT_KEY_HANDLE_PROP_ID,
                        Interop.Crypt32.CertSetPropertyFlags.CERT_SET_PROPERTY_INHIBIT_PERSIST_FLAG,
                        handle))
                    {
                        throw Marshal.GetLastPInvokeError().ToCryptographicException();
                    }

                    // The value was transferred to the certificate.
                    handle.SetHandleAsInvalid();

                    return pal;
                }
                catch
                {
                    pal.Dispose();
                    throw;
                }
            }
        }
    }
}
