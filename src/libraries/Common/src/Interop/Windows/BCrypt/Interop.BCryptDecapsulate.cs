// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

internal static partial class Interop
{
    internal static partial class BCrypt
    {
        [LibraryImport(Libraries.BCrypt)]
        private static unsafe partial NTSTATUS BCryptDecapsulate(
            SafeBCryptKeyHandle hKey,
            byte* pbCipherText,
            uint cbCipherText,
            byte* pbSecretKey,
            uint cbSecretKey,
            out uint pcbSecretKey,
            uint dwFlags);

        internal static unsafe uint BCryptDecapsulate(
            SafeBCryptKeyHandle hKey,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> secretKey,
            uint dwFlags)
        {
            fixed (byte* pCiphertext = ciphertext)
            fixed (byte* pSecretKey = secretKey)
            {
                NTSTATUS status = BCryptDecapsulate(
                    hKey,
                    pCiphertext,
                    (uint)ciphertext.Length,
                    pSecretKey,
                    (uint)secretKey.Length,
                    out uint pcbSecretKey,
                    dwFlags);

                if (status != NTSTATUS.STATUS_SUCCESS)
                {
                    throw CreateCryptographicException(status);
                }

                return pcbSecretKey;
            }
        }
    }
}
