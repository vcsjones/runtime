// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

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

        protected override int UncheckedTransformBlock(ReadOnlySpan<byte> inputBuffer, Span<byte> outputBuffer)
        {
            return BasicSymmetricCipher.Transform(inputBuffer, outputBuffer);
        }

        protected override int UncheckedTransformFinalBlock(ReadOnlySpan<byte> inputBuffer, Span<byte> outputBuffer)
        {
            // The only caller of this method is the array-allocating overload, outputBuffer is
            // always new memory, not a user-provided buffer.
            Debug.Assert(!inputBuffer.Overlaps(outputBuffer));

            int padWritten = SymmetricPadding.CopyAndPadBlock(PaddingSizeBytes, PaddingMode, inputBuffer, outputBuffer);
            int transformWritten = BasicSymmetricCipher.TransformFinal(outputBuffer.Slice(0, padWritten), outputBuffer);

            // After padding, we should have an even number of blocks, and the same applies
            // to the transform.
            Debug.Assert(padWritten == transformWritten);

            return transformWritten;
        }

        protected override byte[] UncheckedTransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            byte[] buffer;
#if NETSTANDARD || NETFRAMEWORK || NETCOREAPP3_0
            buffer = new byte[GetCiphertextLength(inputCount)];
#else
            buffer = GC.AllocateUninitializedArray<byte>(GetCiphertextLength(inputCount));
#endif
            int written = UncheckedTransformFinalBlock(inputBuffer.AsSpan(inputOffset, inputCount), buffer);
            Debug.Assert(written == buffer.Length);
            return buffer;
        }

        private int GetCiphertextLength(int plaintextLength)
        {
            Debug.Assert(plaintextLength >= 0);

             //divisor and factor are same and won't overflow.
            int wholeBlocks = Math.DivRem(plaintextLength, PaddingSizeBytes, out int remainder) * PaddingSizeBytes;

            switch (PaddingMode)
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
                    return checked(wholeBlocks + PaddingSizeBytes);
                default:
                    Debug.Fail($"Unknown padding mode {PaddingMode}.");
                    throw new CryptographicException(SR.Cryptography_UnknownPaddingMode);
            }
        }
    }
}
