// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Internal.Cryptography
{
    internal static class SymmetricCipherHelpers
    {
        public static int GetCiphertextLength(int plaintextLength, int blockSize, PaddingMode paddingMode)
        {
            Debug.Assert(plaintextLength >= 0);
            Debug.Assert(blockSize >= 8 && (blockSize % 8) == 0);

             //divisor and factor are same and won't overflow.
            int wholeBlocks = Math.DivRem(plaintextLength, blockSize, out int remainder) * blockSize;

            switch (paddingMode)
            {
                case PaddingMode.None when (remainder != 0):
                    throw new CryptographicException(SR.Cryptography_PartialBlock);
                case PaddingMode.None:
                case PaddingMode.Zeros when (remainder == 0):
                    return plaintextLength;
                case PaddingMode.Zeros:
                case PaddingMode.PKCS7:
                case PaddingMode.ANSIX923:
                case PaddingMode.ISO10126:
                    int nearestWholeBlock = plaintextLength - remainder;

                    if (int.MaxValue - nearestWholeBlock < blockSize)
                        throw new CryptographicException(SR.Cryptography_PlaintextTooLarge);

                    return nearestWholeBlock + blockSize;
                default:
                    throw new CryptographicException(SR.Cryptography_InvalidPaddingMode);
            }
        }
    }
}
