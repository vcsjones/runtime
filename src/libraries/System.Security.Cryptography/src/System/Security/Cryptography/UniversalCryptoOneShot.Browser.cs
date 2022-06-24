// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;
using System.Security.Cryptography;
using Internal.Cryptography;

namespace System.Security.Cryptography
{
    internal static class UniversalCryptoOneShot
    {
        public static unsafe bool OneShotDecrypt(
            ILiteSymmetricCipher cipher,
            PaddingMode paddingMode,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            out int bytesWritten)
        {
            Debug.Assert(cipher.HandlesPadding);

            if (input.Length % cipher.PaddingSizeInBytes != 0)
                throw new CryptographicException(SR.Cryptography_PartialBlock);

            cipher.ValidatePaddingMode(paddingMode);

            // If the output destination is big enough to hold the decrypted data, including the padding, we can
            // just decrypt to it.
            if (output.Length >= input.Length)
            {
                byteWritten = cipher.TransformFinal(input, output);
                return true;
            }

            byte[] rented = CryptoPool.Rent(input.Length);
            int written = 0;

            try
            {
                written = cipher.TransformFinal(input, rented);

                if (written > output.Length)
                {
                    bytesWritten = 0;
                    return false;
                }

                rented.Slice(0, written).CopyTo(output);
                bytesWritten = written;
                return true;
            }
            finally
            {
                CryptoPool.Return(rented, clearSize: written);
            }
        }

        public static bool OneShotEncrypt(
            ILiteSymmetricCipher cipher,
            PaddingMode paddingMode,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            out int bytesWritten)
        {
            Debug.Assert(cipher.HandlesPadding);
            cipher.ValidatePaddingMode(paddingMode);
            int ciphertextLength = SymmetricPadding.GetCiphertextLength(input.Length, cipher.PaddingSizeInBytes, paddingMode);

            if (output.Length < ciphertextLength)
            {
                bytesWritten = 0;
                return false;
            }

            bytesWritten = cipher.TransformFinal(input, output);
            return true;
        }
    }
}
