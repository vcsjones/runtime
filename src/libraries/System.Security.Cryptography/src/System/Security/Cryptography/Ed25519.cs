// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Versioning;

namespace System.Security.Cryptography
{
    public abstract partial class Ed25519 : EdDsa
    {
        private protected int SignatureSize = 64;

        [UnsupportedOSPlatform("browser")]
        [UnsupportedOSPlatform("windows")]
        [UnsupportedOSPlatform("ios")]
        [UnsupportedOSPlatform("tvos")]
        [UnsupportedOSPlatform("maccatalyst")]
        public static new partial Ed25519 Create();
    }
}
