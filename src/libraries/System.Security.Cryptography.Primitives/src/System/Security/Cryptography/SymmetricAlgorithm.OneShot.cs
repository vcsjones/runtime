// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;

namespace System.Security.Cryptography
{
    public abstract partial class SymmetricAlgorithm
    {
        public byte[] EncryptEcb(byte[] plaintext, PaddingMode paddingMode)
        {
            if (plaintext is null)
                throw new ArgumentNullException(nameof(plaintext));

            return EncryptEcb(new ReadOnlySpan<byte>(plaintext), paddingMode);
        }

        public byte[] EncryptEcb(ReadOnlySpan<byte> plaintext, PaddingMode paddingMode)
        {
            // GetCiphertextLength does validation on the paddingMode parameter,
            // and throws if the plaintext is too large or not block aligned when required.
            int ciphertextLength = GetCiphertextLengthEcb(plaintext.Length, paddingMode);
            byte[] destination = GC.AllocateUninitializedArray<byte>(ciphertextLength);
            bool result = TryEncryptEcbCore(plaintext, destination, paddingMode, out int bytesWritten);

            if (!result)
            {
                // The length should have been pre-validated.
                CryptographicOperations.ZeroMemory(destination);
                throw new CryptographicException();
            }

            Debug.Assert(bytesWritten == ciphertextLength, $"{bytesWritten} == {ciphertextLength}");
            return destination;
        }

        public int EncryptEcb(ReadOnlySpan<byte> plaintext, Span<byte> destination, PaddingMode paddingMode)
        {
            // GetCiphertextLength does validation on the paddingMode parameter,
            // and throws if the plaintext is too large or not block aligned when required.
            int ciphertextLength = GetCiphertextLengthEcb(plaintext.Length, paddingMode);

            if (ciphertextLength > destination.Length)
            {
                throw new ArgumentException(SR.Argument_DestinationTooShort, nameof(destination));
            }

            bool result = TryEncryptEcbCore(plaintext, destination, paddingMode, out int bytesWritten);

            if (!result)
            {
                // The length should have been pre-validated.
                throw new CryptographicException();
            }

            Debug.Assert(bytesWritten == ciphertextLength);
            return bytesWritten;
        }

        public bool TryEncryptEcb(
            ReadOnlySpan<byte> plaintext,
            Span<byte> destination,
            PaddingMode paddingMode,
            out int bytesWritten)
        {
            // GetCiphertextLength does validation on the paddingMode parameter,
            // and throws if the plaintext is too large or not block aligned when required.
            int ciphertextLength = GetCiphertextLengthEcb(plaintext.Length, paddingMode);

            if (ciphertextLength > destination.Length)
            {
                bytesWritten = 0;
                return false;
            }

            bool result = TryEncryptEcbCore(plaintext, destination, paddingMode, out bytesWritten);
            Debug.Assert(result, "The output buffer length should have been pre-validated.");
            return result;
        }

        protected virtual bool TryEncryptEcbCore(
            ReadOnlySpan<byte> plaintext,
            Span<byte> destination,
            PaddingMode paddingMode,
            out int bytesWritten)
        {
            // Non-virtuals should have validated all inputs by now.
            bytesWritten = 0;
            return false;
        }
    }
}
