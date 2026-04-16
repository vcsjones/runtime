// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

internal static partial class Interop
{
    internal static partial class AndroidCrypto
    {
        [LibraryImport(Libraries.AndroidCryptoNative, EntryPoint = "AndroidCryptoNative_X25519IsSupported")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool X25519IsSupported();

        [LibraryImport(Libraries.AndroidCryptoNative, EntryPoint = "AndroidCryptoNative_X25519DestroyKey")]
        internal static partial void X25519DestroyKey(IntPtr key);

        [LibraryImport(Libraries.AndroidCryptoNative, EntryPoint = "AndroidCryptoNative_X25519GenerateKey")]
        private static partial int X25519GenerateKeyNative(
            out SafeX25519PublicKeyHandle publicKey,
            out SafeX25519PrivateKeyHandle privateKey);

        internal static void X25519GenerateKey(
            out SafeX25519PublicKeyHandle publicKey,
            out SafeX25519PrivateKeyHandle privateKey)
        {
            int result = X25519GenerateKeyNative(out publicKey, out privateKey);

            if (result != 1)
            {
                publicKey.Dispose();
                privateKey.Dispose();
                throw new CryptographicException();
            }
        }
    }
}

namespace System.Security.Cryptography
{
    internal sealed class SafeX25519PublicKeyHandle : SafeHandle
    {
        public SafeX25519PublicKeyHandle()
            : base(IntPtr.Zero, ownsHandle: true)
        {
        }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            Interop.AndroidCrypto.X25519DestroyKey(handle);
            SetHandle(IntPtr.Zero);
            return true;
        }
    }

    internal sealed class SafeX25519PrivateKeyHandle : SafeHandle
    {
        public SafeX25519PrivateKeyHandle()
            : base(IntPtr.Zero, ownsHandle: true)
        {
        }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            Interop.AndroidCrypto.X25519DestroyKey(handle);
            SetHandle(IntPtr.Zero);
            return true;
        }
    }
}
