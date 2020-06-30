// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Internal.Cryptography
{
    //
    // A cross-platform ICryptoTransform implementation for encryption.
    //
    //  - Implements the various padding algorithms (as we support padding algorithms that the underlying native apis don't.)
    //
    //  - Parameterized by a BasicSymmetricCipher which encapsulates the algorithm, key, IV, chaining mode, direction of encryption
    //    and the underlying native apis implementing the encryption.
    //
    internal sealed class UniversalCryptoEncryptor : UniversalCryptoTransform
    {
        public UniversalCryptoEncryptor(PaddingMode paddingMode, BasicSymmetricCipher basicSymmetricCipher)
            : base(paddingMode, basicSymmetricCipher)
        {
        }

        protected sealed override int UncheckedTransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            return BasicSymmetricCipher.Transform(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
        }

        protected sealed override unsafe byte[] UncheckedTransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            byte[] paddedBlock = CryptoPool.Rent(inputCount + InputBlockSize * 2);
            int written = paddedBlock.Length;

            try
            {
                ReadOnlySpan<byte> inputBufferSpan = new ReadOnlySpan<byte>(inputBuffer, inputOffset, inputCount);
                written = SymmetricPaddingHelpers.PadBlock(PaddingMode, InputBlockSize, inputBufferSpan, paddedBlock);

                fixed (byte* paddedBlockPtr = paddedBlock)
                {
                    return BasicSymmetricCipher.TransformFinal(paddedBlock, 0, written);
                }
            }
            finally
            {
                CryptoPool.Return(paddedBlock, clearSize: written);
            }
        }
    }
}
