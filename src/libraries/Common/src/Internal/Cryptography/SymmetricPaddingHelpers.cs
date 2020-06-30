// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Internal.Cryptography
{
    internal static class SymmetricPaddingHelpers
    {
        internal static int PadBlock(PaddingMode paddingMode, int blockSizeInBytes, ReadOnlySpan<byte> block, Span<byte> destination)
        {
            Debug.Assert(paddingMode >= PaddingMode.None && paddingMode <= PaddingMode.ISO10126);
            Debug.Assert(blockSizeInBytes > 0);

            int count = block.Length;
            int paddingRemainder = count % blockSizeInBytes;
            int padBytes = blockSizeInBytes - paddingRemainder;

            switch (paddingMode)
            {
                case PaddingMode.None when (paddingRemainder != 0):
                    throw new CryptographicException(SR.Cryptography_PartialBlock);

                case PaddingMode.None:
                    if (destination.Length < count)
                    {
                        throw new ArgumentException(SR.Argument_DestinationTooShort, nameof(destination));
                    }

                    block.CopyTo(destination);
                    return count;

                // ANSI padding fills the blocks with zeros and adds the total number of padding bytes as
                // the last pad byte, adding an extra block if the last block is complete.
                //
                // xx 00 00 00 00 00 00 07
                case PaddingMode.ANSIX923:
                    int ansiSize = count + padBytes;

                    if (destination.Length < ansiSize)
                    {
                        throw new ArgumentException(SR.Argument_DestinationTooShort, nameof(destination));
                    }

                    block.CopyTo(destination);
                    destination.Slice(count, padBytes - 1).Clear();
                    destination[count + padBytes - 1] = (byte)padBytes;
                    return ansiSize;

                // ISO padding fills the blocks up with random bytes and adds the total number of padding
                // bytes as the last pad byte, adding an extra block if the last block is complete.
                //
                // xx rr rr rr rr rr rr 07
                case PaddingMode.ISO10126:
                    int isoSize = count + padBytes;

                    if (destination.Length < isoSize)
                    {
                        throw new ArgumentException(SR.Argument_DestinationTooShort, nameof(destination));
                    }

                    block.CopyTo(destination);
                    RandomNumberGenerator.Fill(destination.Slice(count, padBytes - 1));
                    destination[count + padBytes - 1] = (byte)padBytes;
                    return isoSize;

                // PKCS padding fills the blocks up with bytes containing the total number of padding bytes
                // used, adding an extra block if the last block is complete.
                //
                // xx xx 06 06 06 06 06 06
                case PaddingMode.PKCS7:
                    int pkcsSize = count + padBytes;

                    if (destination.Length < pkcsSize)
                    {
                        throw new ArgumentException(SR.Argument_DestinationTooShort, nameof(destination));
                    }

                    block.CopyTo(destination);
                    destination.Slice(count, padBytes).Fill((byte)padBytes);
                    return pkcsSize;

                // Zeros padding fills the last partial block with zeros, and does not add a new block to
                // the end if the last block is already complete.
                //
                //  xx 00 00 00 00 00 00 00
                case PaddingMode.Zeros:
                    if (padBytes == blockSizeInBytes)
                    {
                        padBytes = 0;
                    }

                    int zeroSize = count + padBytes;

                    if (destination.Length < zeroSize)
                    {
                        throw new ArgumentException(SR.Argument_DestinationTooShort, nameof(destination));
                    }

                    destination.Slice(0, zeroSize).Clear();
                    block.CopyTo(destination);
                    return zeroSize;

                default:
                    throw new CryptographicException(SR.Cryptography_UnknownPaddingMode);
            }
        }
    }
}
