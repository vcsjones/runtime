// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;

namespace System.Security.Cryptography
{
    internal sealed class X25519DiffieHellmanImplementation : X25519DiffieHellman
    {
        private SafeEvpPKeyHandle _key;

        internal static new bool IsSupported => true;

        private X25519DiffieHellmanImplementation(SafeEvpPKeyHandle key)
        {
            _key = key;
        }

        protected override void ExportPrivateKeyCore(Span<byte> destination)
        {
            Debug.Assert(destination.Length == PrivateKeySizeInBytes);
            Interop.Crypto.X25519ExportPrivateKey(_key, destination);
        }

        protected override void ExportPublicKeyCore(Span<byte> destination)
        {
            Debug.Assert(destination.Length == PublicKeySizeInBytes);
            Interop.Crypto.X25519ExportPublicKey(_key, destination);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _key.Dispose();
            }

            base.Dispose(disposing);
        }

        internal static X25519DiffieHellmanImplementation GenerateKeyImpl()
        {
            Debug.Assert(IsSupported);
            SafeEvpPKeyHandle key = Interop.Crypto.X25519GenerateKey();
            Debug.Assert(!key.IsInvalid);
            return new X25519DiffieHellmanImplementation(key);
        }
    }
}
