// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

internal static partial class Interop
{
    internal static partial class AppleCrypto
    {
        // Must be in sync with pal_signverify.h
        internal enum PAL_SignatureAlgorithm
        {
            Unknown = 0,
            RSA = 1,
            EC = 2,
            DSA = 3,
        }
    }
}
