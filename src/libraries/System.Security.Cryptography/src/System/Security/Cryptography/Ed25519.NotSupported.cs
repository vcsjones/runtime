// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Security.Cryptography
{
    public abstract partial class Ed25519
    {
        public static new partial Ed25519 Create()
        {
            throw new PlatformNotSupportedException();
        }
    }
}
