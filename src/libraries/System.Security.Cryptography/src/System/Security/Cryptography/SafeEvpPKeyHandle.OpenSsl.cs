// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace System.Security.Cryptography
{
    public sealed partial class SafeEvpPKeyHandle : SafeHandle
    {
        internal static readonly SafeEvpPKeyHandle InvalidHandle = new SafeEvpPKeyHandle();

        /// <summary>
        /// In some cases like when a key is loaded from a provider, the key may have an associated data
        /// we need to keep alive for the lifetime of the key. This field is used to track that data.
        /// </summary>
        internal IntPtr ExtraHandle { get; private set; }

        [UnsupportedOSPlatform("android")]
        [UnsupportedOSPlatform("browser")]
        [UnsupportedOSPlatform("ios")]
        [UnsupportedOSPlatform("tvos")]
        [UnsupportedOSPlatform("windows")]
        public SafeEvpPKeyHandle() :
            base(IntPtr.Zero, ownsHandle: true)
        {
        }

        [UnsupportedOSPlatform("android")]
        [UnsupportedOSPlatform("browser")]
        [UnsupportedOSPlatform("ios")]
        [UnsupportedOSPlatform("tvos")]
        [UnsupportedOSPlatform("windows")]
        public SafeEvpPKeyHandle(IntPtr handle, bool ownsHandle)
            : base(handle, ownsHandle)
        {
        }

        internal SafeEvpPKeyHandle(IntPtr handle, IntPtr extraHandle)
            : base(handle, ownsHandle: true)
        {
            ExtraHandle = extraHandle;
        }

        protected override bool ReleaseHandle()
        {
            Interop.Crypto.EvpPkeyDestroy(handle, ExtraHandle);
            ExtraHandle = IntPtr.Zero;

            SetHandle(IntPtr.Zero);
            return true;
        }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero; }
        }

        /// <summary>
        /// Create another instance of SafeEvpPKeyHandle which has an independent lifetime
        /// from this instance, but tracks the same resource.
        /// </summary>
        /// <returns>An equivalent SafeEvpPKeyHandle with a different lifetime</returns>
        public SafeEvpPKeyHandle DuplicateHandle()
        {
            if (IsInvalid)
                throw new InvalidOperationException(SR.Cryptography_OpenInvalidHandle);

            // Reliability: Allocate the SafeHandle before calling UpRefEvpPkey so
            // that we don't lose a tracked reference in low-memory situations.
            SafeEvpPKeyHandle safeHandle = new SafeEvpPKeyHandle();

            int success = Interop.Crypto.UpRefEvpPkey(this);

            if (success != 1)
            {
                Debug.Fail("Called UpRefEvpPkey on a key which was already marked for destruction");
                Exception e = Interop.Crypto.CreateOpenSslCryptographicException();
                safeHandle.Dispose();
                throw e;
            }

            // Since we didn't actually create a new handle, copy the handle
            // to the new SafeHandle.
            safeHandle.SetHandle(handle);
            // ExtraHandle is upref'd by UpRefEvpPkey
            safeHandle.ExtraHandle = ExtraHandle;
            return safeHandle;
        }

        /// <summary>
        ///   Open a named private key using a named OpenSSL <code>ENGINE</code>.
        /// </summary>
        /// <param name="engineName">
        ///   The name of the <code>ENGINE</code> to process the private key open request.
        /// </param>
        /// <param name="keyId">
        ///   The name of the key to open.
        /// </param>
        /// <returns>
        ///   The opened key.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="engineName"/> or <paramref name="keyId"/> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="engineName"/> or <paramref name="keyId"/> is the empty string.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   the key could not be opened via the specified ENGINE.
        /// </exception>
        /// <remarks>
        ///   <para>
        ///     This operation will fail if OpenSSL cannot successfully load the named <code>ENGINE</code>,
        ///     or if the named <code>ENGINE</code> cannot load the named key.
        ///   </para>
        ///   <para>
        ///     Not all <code>ENGINE</code>s support loading private keys.
        ///   </para>
        ///   <para>
        ///     The syntax for <paramref name="keyId"/> is determined by each individual
        ///     <code>ENGINE</code>.
        ///   </para>
        /// </remarks>
        [UnsupportedOSPlatform("android")]
        [UnsupportedOSPlatform("browser")]
        [UnsupportedOSPlatform("ios")]
        [UnsupportedOSPlatform("tvos")]
        [UnsupportedOSPlatform("windows")]
        public static SafeEvpPKeyHandle OpenPrivateKeyFromEngine(string engineName, string keyId)
        {
            ArgumentException.ThrowIfNullOrEmpty(engineName);
            ArgumentException.ThrowIfNullOrEmpty(keyId);

            if (!Interop.OpenSslNoInit.OpenSslIsAvailable)
            {
                throw new PlatformNotSupportedException(SR.PlatformNotSupported_CryptographyOpenSSL);
            }

            return Interop.Crypto.LoadPrivateKeyFromEngine(engineName, keyId);
        }

        /// <summary>
        ///   Open a named public key using a named OpenSSL <code>ENGINE</code>.
        /// </summary>
        /// <param name="engineName">
        ///   The name of the <code>ENGINE</code> to process the public key open request.
        /// </param>
        /// <param name="keyId">
        ///   The name of the key to open.
        /// </param>
        /// <returns>
        ///   The opened key.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="engineName"/> or <paramref name="keyId"/> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="engineName"/> or <paramref name="keyId"/> is the empty string.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   the key could not be opened via the specified ENGINE.
        /// </exception>
        /// <remarks>
        ///   <para>
        ///     This operation will fail if OpenSSL cannot successfully load the named <code>ENGINE</code>,
        ///     or if the named <code>ENGINE</code> cannot load the named key.
        ///   </para>
        ///   <para>
        ///     Not all <code>ENGINE</code>s support loading public keys, even ones that support
        ///     loading private keys.
        ///   </para>
        ///   <para>
        ///     The syntax for <paramref name="keyId"/> is determined by each individual
        ///     <code>ENGINE</code>.
        ///   </para>
        /// </remarks>
        [UnsupportedOSPlatform("android")]
        [UnsupportedOSPlatform("browser")]
        [UnsupportedOSPlatform("ios")]
        [UnsupportedOSPlatform("tvos")]
        [UnsupportedOSPlatform("windows")]
        public static SafeEvpPKeyHandle OpenPublicKeyFromEngine(string engineName, string keyId)
        {
            ArgumentException.ThrowIfNullOrEmpty(engineName);
            ArgumentException.ThrowIfNullOrEmpty(keyId);

            if (!Interop.OpenSslNoInit.OpenSslIsAvailable)
            {
                throw new PlatformNotSupportedException(SR.PlatformNotSupported_CryptographyOpenSSL);
            }

            return Interop.Crypto.LoadPublicKeyFromEngine(engineName, keyId);
        }

        /// <summary>
        ///   Open a key using a named <c>OSSL_PROVIDER</c>.
        /// </summary>
        /// <param name="providerName">
        ///   The name of the <c>OSSL_PROVIDER</c> to process the key open request.
        /// </param>
        /// <param name="keyUri">
        ///   The URI assigned by the <c>OSSL_PROVIDER</c> of the key to open.
        /// </param>
        /// <returns>
        ///   The opened key.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="providerName"/> or <paramref name="keyUri"/> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="providerName"/> or <paramref name="keyUri"/> is the empty string.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   the key could not be opened via the specified named <c>OSSL_PROVIDER</c>.
        /// </exception>
        /// <remarks>
        ///   <para>
        ///     Both <paramref name="providerName" /> and <paramref name="keyUri" /> must be trusted inputs.
        ///   </para>
        ///   <para>
        ///     This operation will fail if OpenSSL cannot successfully load the named <c>OSSL_PROVIDER</c>,
        ///     or if the named <c>OSSL_PROVIDER</c> cannot load the named key.
        ///   </para>
        ///   <para>
        ///     The syntax for <paramref name="keyUri"/> is determined by each individual
        ///     named <c>OSSL_PROVIDER</c>.
        ///   </para>
        /// </remarks>
        [UnsupportedOSPlatform("android")]
        [UnsupportedOSPlatform("browser")]
        [UnsupportedOSPlatform("ios")]
        [UnsupportedOSPlatform("tvos")]
        [UnsupportedOSPlatform("windows")]
        public static SafeEvpPKeyHandle OpenKeyFromProvider(string providerName, string keyUri)
        {
            ArgumentException.ThrowIfNullOrEmpty(providerName);
            ArgumentException.ThrowIfNullOrEmpty(keyUri);

            return OpenKeyFromProviderCore([providerName], keyUri, propertyQuery: null);
        }

        /// <summary>
        ///   Open a key using the specified <c>OSSL_PROVIDER</c> instances.
        /// </summary>
        /// <param name="providerNames">
        ///   The names of the <c>OSSL_PROVIDER</c> instances to load into the library context.
        /// </param>
        /// <param name="keyUri">
        ///   The URI of the key to open.
        /// </param>
        /// <param name="propertyQuery">
        ///   An optional property query string to use when opening the key store.
        /// </param>
        /// <returns>
        ///   The opened key.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="providerNames"/> or <paramref name="keyUri"/> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="keyUri"/> is the empty string, or <paramref name="providerNames"/> is empty
        ///   or contains an element that is <see langword="null" /> or empty.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   The key could not be opened via the specified providers.
        /// </exception>
        /// <remarks>
        ///   <para>
        ///     The values in <paramref name="providerNames" />, <paramref name="keyUri" />,
        ///     and <paramref name="propertyQuery" /> must be trusted inputs.
        ///   </para>
        ///   <para>
        ///     This operation will fail if OpenSSL cannot successfully load any of the named
        ///     <c>OSSL_PROVIDER</c> instances, or if the providers cannot load the named key.
        ///   </para>
        ///   <para>
        ///     The syntax for <paramref name="keyUri"/> is determined by the loaded providers.
        ///   </para>
        /// </remarks>
        [UnsupportedOSPlatform("android")]
        [UnsupportedOSPlatform("browser")]
        [UnsupportedOSPlatform("ios")]
        [UnsupportedOSPlatform("tvos")]
        [UnsupportedOSPlatform("windows")]
        public static SafeEvpPKeyHandle OpenKeyFromProvider(IEnumerable<string> providerNames, string keyUri, string? propertyQuery = null)
        {
            ArgumentNullException.ThrowIfNull(providerNames);
            ArgumentException.ThrowIfNullOrEmpty(keyUri);

            string[] providerNamesArray = new string[8];
            int count = 0;

            foreach (string name in providerNames)
            {
                if (string.IsNullOrEmpty(name))
                {
                    throw new ArgumentException(SR.Arg_NullOrEmptyCollectionElement, nameof(providerNames));
                }

                if (count == providerNamesArray.Length)
                {
                    Array.Resize(ref providerNamesArray, providerNamesArray.Length * 2);
                }

                providerNamesArray[count] = name;
                count++;
            }

            if (count == 0)
            {
                throw new ArgumentException(SR.Arg_EmptyOrNullArray, nameof(providerNames));
            }

            return OpenKeyFromProviderCore(providerNamesArray.AsSpan(0, count), keyUri, propertyQuery);
        }

        private static SafeEvpPKeyHandle OpenKeyFromProviderCore(ReadOnlySpan<string> providerNames, string keyUri, string? propertyQuery)
        {
            if (!Interop.OpenSslNoInit.OpenSslIsAvailable)
            {
                throw new PlatformNotSupportedException(SR.PlatformNotSupported_CryptographyOpenSSL);
            }

            return Interop.Crypto.LoadKeyFromProvider(providerNames, keyUri, propertyQuery);
        }
    }
}
