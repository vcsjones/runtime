// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.Win32.SafeHandles;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

using static Interop.Crypt32;

namespace Internal.Cryptography.Pal.Native
{
    /// <summary>
    /// SafeHandle for the CERT_CONTEXT structure defined by crypt32. Unlike SafeCertContextHandle, disposition already deletes any associated key containers.
    /// </summary>
    internal sealed class SafeCertContextHandleWithKeyContainerDeletion : SafeCertContextHandle
    {
        protected sealed override bool ReleaseHandle()
        {
            using (SafeCertContextHandle certContext = Interop.crypt32.CertDuplicateCertificateContext(handle))
            {
                DeleteKeyContainer(certContext);
            }
            base.ReleaseHandle();
            return true;
        }

        public static void DeleteKeyContainer(SafeCertContextHandle pCertContext)
        {
            if (pCertContext.IsInvalid)
                return;

            int cb = 0;
            bool containsPrivateKey = Interop.crypt32.CertGetCertificateContextProperty(pCertContext, CertContextPropId.CERT_KEY_PROV_INFO_PROP_ID, null, ref cb);
            if (!containsPrivateKey)
                return;

            byte[] provInfoAsBytes = new byte[cb];
            if (!Interop.crypt32.CertGetCertificateContextProperty(pCertContext, CertContextPropId.CERT_KEY_PROV_INFO_PROP_ID, provInfoAsBytes, ref cb))
                return;

            unsafe
            {
                fixed (byte* pProvInfoAsBytes = provInfoAsBytes)
                {
                    CRYPT_KEY_PROV_INFO* pProvInfo = (CRYPT_KEY_PROV_INFO*)pProvInfoAsBytes;

                    if (pProvInfo->dwProvType == 0)
                    {
                        // dwProvType being 0 indicates that the key is stored in CNG.
                        // dwProvType being non-zero indicates that the key is stored in CAPI.

                        string providerName = Marshal.PtrToStringUni((IntPtr)(pProvInfo->pwszProvName))!;
                        string keyContainerName = Marshal.PtrToStringUni((IntPtr)(pProvInfo->pwszContainerName))!;

                        try
                        {
                            using (CngKey cngKey = CngKey.Open(keyContainerName, new CngProvider(providerName)))
                            {
                                cngKey.Delete();
                            }
                        }
                        catch (CryptographicException)
                        {
                            // While leaving the file on disk is undesirable, an inability to perform this cleanup
                            // should not manifest itself to a user.
                        }
                    }
                    else
                    {
                        CryptAcquireContextFlags flags = (pProvInfo->dwFlags & CryptAcquireContextFlags.CRYPT_MACHINE_KEYSET) | CryptAcquireContextFlags.CRYPT_DELETEKEYSET;
                        IntPtr hProv;
                        _ = Interop.cryptoapi.CryptAcquireContext(out hProv, pProvInfo->pwszContainerName, pProvInfo->pwszProvName, pProvInfo->dwProvType, flags);

                        // Called CryptAcquireContext solely for the side effect of deleting the key containers. When called with these flags, no actual
                        // hProv is returned (so there's nothing to clean up.)
                        Debug.Assert(hProv == IntPtr.Zero);
                    }
                }
            }
        }
    }

    /// <summary>
    /// SafeHandle for the HCERTSTORE handle defined by crypt32.
    /// </summary>
    internal sealed class SafeCertStoreHandle : SafePointerHandle<SafeCertStoreHandle>
    {
        protected sealed override bool ReleaseHandle()
        {
            bool success = Interop.Crypt32.CertCloseStore(handle, 0);
            return success;
        }
    }

    /// <summary>
    /// SafeHandle for the HCRYPTMSG handle defined by crypt32.
    /// </summary>
    internal sealed class SafeCryptMsgHandle : SafePointerHandle<SafeCryptMsgHandle>
    {
        protected sealed override bool ReleaseHandle()
        {
            bool success = Interop.Crypt32.CryptMsgClose(handle);
            return success;
        }
    }

    /// <summary>
    /// SafeHandle for LocalAlloc'd memory.
    /// </summary>
    internal sealed class SafeLocalAllocHandle : SafePointerHandle<SafeLocalAllocHandle>
    {
        public static SafeLocalAllocHandle Create(int cb)
        {
            var h = new SafeLocalAllocHandle();
            h.SetHandle(Marshal.AllocHGlobal(cb));
            return h;
        }

        protected sealed override bool ReleaseHandle()
        {
            Marshal.FreeHGlobal(handle);
            return true;
        }
    }

    internal sealed class SafeChainEngineHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeChainEngineHandle()
            : base(true)
        {
        }

        private SafeChainEngineHandle(IntPtr handle)
            : base(true)
        {
            SetHandle(handle);
        }

        public static readonly SafeChainEngineHandle MachineChainEngine =
            new SafeChainEngineHandle((IntPtr)ChainEngine.HCCE_LOCAL_MACHINE);

        public static readonly SafeChainEngineHandle UserChainEngine =
            new SafeChainEngineHandle((IntPtr)ChainEngine.HCCE_CURRENT_USER);

        protected sealed override bool ReleaseHandle()
        {
            Interop.crypt32.CertFreeCertificateChainEngine(handle);
            SetHandle(IntPtr.Zero);
            return true;
        }

        protected override void Dispose(bool disposing)
        {
            if (this != UserChainEngine && this != MachineChainEngine)
            {
                base.Dispose(disposing);
            }
        }
    }
}
