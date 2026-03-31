// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;

namespace System.Security.Cryptography
{
    internal sealed class X25519DiffieHellmanImplementation : X25519DiffieHellman
    {
        internal static new bool IsSupported => false;

        protected override void ExportPublicKeyCore(Span<byte> destination)
        {
            Debug.Fail("Caller should have checked platform availability.");
            throw new PlatformNotSupportedException();
        }

        internal static X25519DiffieHellmanImplementation GenerateKeyImpl()
        {
            Debug.Fail("Caller should have checked platform availability.");
            throw new PlatformNotSupportedException();
        }
    }
}
