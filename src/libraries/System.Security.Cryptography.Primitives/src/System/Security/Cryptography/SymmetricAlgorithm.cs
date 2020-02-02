// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Internal.Cryptography;

namespace System.Security.Cryptography
{
    public abstract partial class SymmetricAlgorithm : IDisposable
    {
        protected SymmetricAlgorithm()
        {
            ModeValue = CipherMode.CBC;
            PaddingValue = PaddingMode.PKCS7;
        }

        public static SymmetricAlgorithm Create() =>
            throw new PlatformNotSupportedException(SR.Cryptography_DefaultAlgorithm_NotSupported);

        public static SymmetricAlgorithm? Create(string algName) =>
            (SymmetricAlgorithm?)CryptoConfigForwarder.CreateFromName(algName);

        public virtual int FeedbackSize
        {
            get
            {
                return FeedbackSizeValue;
            }
            set
            {
                if (value <= 0 || value > BlockSizeValue || (value % 8) != 0)
                    throw new CryptographicException(SR.Cryptography_InvalidFeedbackSize);
                FeedbackSizeValue = value;
            }
        }

        public virtual int BlockSize
        {
            get
            {
                return BlockSizeValue;
            }

            set
            {
                bool validatedByZeroSkipSizeKeySizes;
                if (!value.IsLegalSize(this.LegalBlockSizes, out validatedByZeroSkipSizeKeySizes))
                    throw new CryptographicException(SR.Cryptography_InvalidBlockSize);

                if (BlockSizeValue == value && !validatedByZeroSkipSizeKeySizes) // The !validatedByZeroSkipSizeKeySizes check preserves a very obscure back-compat behavior.
                    return;

                BlockSizeValue = value;
                IVValue = null;
                return;
            }
        }

        public virtual byte[] IV
        {
            get
            {
                if (IVValue == null)
                    GenerateIV();
                return IVValue.CloneByteArray()!;
            }

            set
            {
                if (value == null)
                    throw new ArgumentNullException(nameof(value));
                if (value.Length != this.BlockSize / 8)
                    throw new CryptographicException(SR.Cryptography_InvalidIVSize);

                IVValue = value.CloneByteArray();
            }
        }

        public virtual byte[] Key
        {
            get
            {
                if (KeyValue == null)
                    GenerateKey();
                return KeyValue.CloneByteArray()!;
            }

            set
            {
                if (value == null)
                    throw new ArgumentNullException(nameof(value));

                long bitLength = value.Length * 8L;
                if (bitLength > int.MaxValue || !ValidKeySize((int)bitLength))
                    throw new CryptographicException(SR.Cryptography_InvalidKeySize);

                // must convert bytes to bits
                this.KeySize = (int)bitLength;
                KeyValue = value.CloneByteArray();
            }
        }

        public virtual int KeySize
        {
            get
            {
                return KeySizeValue;
            }

            set
            {
                if (!ValidKeySize(value))
                    throw new CryptographicException(SR.Cryptography_InvalidKeySize);

                KeySizeValue = value;
                KeyValue = null;
            }
        }

        public virtual KeySizes[] LegalBlockSizes
        {
            get
            {
                // .NET Framework compat: No null check is performed.
                return (KeySizes[])LegalBlockSizesValue!.Clone();
            }
        }

        public virtual KeySizes[] LegalKeySizes
        {
            get
            {
                // .NET Framework compat: No null check is performed.
                return (KeySizes[])LegalKeySizesValue!.Clone();
            }
        }

        public virtual CipherMode Mode
        {
            get
            {
                return ModeValue;
            }

            set
            {
                if (!(value == CipherMode.CBC || value == CipherMode.ECB))
                    throw new CryptographicException(SR.Cryptography_InvalidCipherMode);

                ModeValue = value;
            }
        }

        public virtual PaddingMode Padding
        {
            get
            {
                return PaddingValue;
            }

            set
            {
                if ((value < PaddingMode.None) || (value > PaddingMode.ISO10126))
                    throw new CryptographicException(SR.Cryptography_InvalidPaddingMode);
                PaddingValue = value;
            }
        }

        public virtual ICryptoTransform CreateDecryptor()
        {
            return CreateDecryptor(Key, IV);
        }

        public abstract ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV);

        public virtual ICryptoTransform CreateEncryptor()
        {
            return CreateEncryptor(Key, IV);
        }

        public abstract ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[]? rgbIV);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public void Clear()
        {
            (this as IDisposable).Dispose();
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (KeyValue != null)
                {
                    Array.Clear(KeyValue, 0, KeyValue.Length);
                    KeyValue = null;
                }
                if (IVValue != null)
                {
                    Array.Clear(IVValue, 0, IVValue.Length);
                    IVValue = null;
                }
            }
        }

        public abstract void GenerateIV();

        public abstract void GenerateKey();

        public bool ValidKeySize(int bitLength)
        {
            KeySizes[] validSizes = this.LegalKeySizes;
            if (validSizes == null)
                return false;
            return bitLength.IsLegalSize(validSizes);
        }

        /// <summary>
        ///   Determines the length of ciphertext given the length of the plaintext
        ///   with a given padding mode.
        /// </summary>
        /// <param name="paddingMode">
        ///   The padding mode used to determine the ciphertext's length.
        /// </param>
        /// <param name="plaintextLength">
        ///   The length of the plaintext to determine the length of the ciphertext.
        /// </param>
        /// <returns>
        ///   The length of the ciphertext, including padding.
        /// </returns>
        /// <exception cref="ArgumentOutOfRangeException">
        ///   <paramref name="plaintextLength"/> is not zero or positive.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        ///   <paramref name="plaintextLength"/> is invalid for the specified
        ///   <paramref name="paddingMode" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="paddingMode" /> is not valid.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   The implementation's <c>BlockSize</c> does not divide evenly in to bytes from bits.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   The <paramref name="plaintextLength" /> is too long for the <paramref name="paddingMode" />
        ///   and will result in a ciphertext length that overflows.
        /// </exception>

        public int GetCiphertextLength(PaddingMode paddingMode, int plaintextLength)
        {
            if (plaintextLength < 0)
                throw new ArgumentOutOfRangeException(nameof(plaintextLength),
                    SR.ArgumentOutOfRange_NeedNonNegNum);

            if (BlockSize <= 0 || (BlockSize & 0b111) != 0)
                throw new CryptographicException(SR.Cryptography_UnsupportedBlockSize);

            int blockSizeBytes = BlockSize / 8;
            int remainder = plaintextLength % blockSizeBytes;

            switch (paddingMode)
            {
                case PaddingMode.None when (remainder != 0):
                    throw new ArgumentOutOfRangeException(nameof(plaintextLength), SR.Cryptography_MatchBlockSize);
                case PaddingMode.None:
                case PaddingMode.Zeros when (remainder == 0):
                    return plaintextLength;
                case PaddingMode.Zeros:
                case PaddingMode.PKCS7:
                case PaddingMode.ANSIX923:
                case PaddingMode.ISO10126:
                    int nearestWholeBlock = plaintextLength - remainder;

                    if (int.MaxValue - nearestWholeBlock < blockSizeBytes)
                        throw new CryptographicException(SR.Cryptography_PlaintextTooLarge);

                    return nearestWholeBlock + blockSizeBytes;
                default:
                    throw new ArgumentException(SR.Cryptography_InvalidPaddingMode, nameof(paddingMode));
            }
        }

        /// <summary>
        ///   Encrypts plaintext data with the specified padding mode using ECB.
        /// </summary>
        /// <param name="plaintext">
        ///   The plaintext data to encrypt.
        /// </param>
        /// <param name="paddingMode">
        ///   The padding mode to use when encrypting the plaintext data.
        /// </param>
        /// <returns>
        ///   The ciphertext data, encrypted with the <c>Key</c>.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   Thrown when <paramref name="plaintext" /> is <c>null</c>.
        /// </exception>
        public byte[] EncryptEcb(byte[] plaintext, PaddingMode paddingMode)
        {
            if (plaintext is null)
                throw new ArgumentNullException(nameof(plaintext));

            return EncryptEcb(plaintext.AsSpan(), paddingMode);
        }

        /// <summary>
        ///   Encrypts plaintext data with the specified padding mode using ECB.
        /// </summary>
        /// <param name="plaintext">
        ///   The plaintext data to encrypt.
        /// </param>
        /// <param name="paddingMode">
        ///   The padding mode to use when encrypting the plaintext data.
        /// </param>
        /// <returns>
        ///   The ciphertext data, encrypted with the <c>Key</c>.
        /// </returns>
        public byte[] EncryptEcb(ReadOnlySpan<byte> plaintext, PaddingMode paddingMode)
        {
            int bufferSize = GetCiphertextLength(paddingMode, plaintext.Length);
            byte[] buffer = new byte[bufferSize];

            if (!TryEncryptEcb(plaintext, buffer, paddingMode, out _))
            {
                Debug.Fail("Allocated buffer is too small.");
                throw new CryptographicException(SR.Argument_BufferTooSmall);
            }

            return buffer;
        }

        /// <summary>
        ///   Encrypts plaintext data with the specified padding mode using ECB,
        ///   writing the ciphertext to a destination buffer.
        /// </summary>
        /// <param name="plaintext">
        ///   The plaintext data to encrypt.
        /// </param>
        /// <param name="destination">
        ///   The destination buffer to write the ciphertext, encrypted with
        ///   the <c>Key</c>.
        /// </param>
        /// <param name="paddingMode">
        ///   The padding mode to use when encrypting the plaintext data.
        /// </param>
        /// <returns>
        ///   The number of bytes written to <paramref name="destination" />.
        /// </returns>
        /// <exception cref="CryptographicException">
        ///   Thrown when the <paramref name="destination" /> buffer is too small.
        /// </exception>
        public int EncyptEcb(
            ReadOnlySpan<byte> plaintext,
            Span<byte> destination,
            PaddingMode paddingMode
        )
        {
            if (!TryEncryptEcb(plaintext, destination, paddingMode, out int bytesWritten))
            {
                throw new CryptographicException(SR.Argument_BufferTooSmall);
            }

            return bytesWritten;
        }

        /// <summary>
        ///   Encrypts plaintext data with the specified padding mode using ECB,
        ///   writing the ciphertext to a destination buffer.
        /// </summary>
        /// <param name="plaintext">
        ///   The plaintext data to encrypt.
        /// </param>
        /// <param name="destination">
        ///   The destination buffer to write the ciphertext, encrypted with
        ///   the <c>Key</c>.
        /// </param>
        /// <param name="paddingMode">
        ///   The padding mode to use when encrypting the plaintext data.
        /// </param>
        /// <param name="bytesWritten">
        ///   Outputs the number of bytes written to <paramref name="destination" />.
        /// </param>
        /// <returns>
        ///   True if the operation succeeded, otherwise false.
        /// </returns>
        public bool TryEncryptEcb(
            ReadOnlySpan<byte> plaintext,
            Span<byte> destination,
            PaddingMode paddingMode,
            out int bytesWritten
        ) =>
            TryEncryptEcbCore(plaintext, destination, paddingMode, out bytesWritten);

        /// <summary>
        ///   The base implementation for <c>EncryptEcb</c> and <c>TryEncryptEcb</c>.
        /// </summary>
        /// <param name="plaintext">
        ///   The plaintext data to encrypt.
        /// </param>
        /// <param name="destination">
        ///   The destination buffer to write the ciphertext, encrypted with
        ///   the <c>Key</c>.
        /// </param>
        /// <param name="paddingMode">
        ///   The padding mode to use when encrypting the plaintext data.
        /// </param>
        /// <param name="bytesWritten">
        ///   Outputs the number of bytes written to <paramref name="destination" />.
        /// </param>
        /// <returns>
        ///   True if the operation succeeded, otherwise false.
        /// </returns>
        /// <remarks>
        ///   Derived classes should override this to provide a purpose-built implementation
        ///   of ECB encryption. Otherwise, a generic implementation is provided using
        ///   <see cref="CreateEncryptor()" />.
        /// </remarks>
        protected virtual bool TryEncryptEcbCore(
            ReadOnlySpan<byte> plaintext,
            Span<byte> destination,
            PaddingMode paddingMode,
            out int bytesWritten
        )
        {
            return TryTransformInternal(
                plaintext,
                destination,
                paddingMode,
                encrypt: true,
                CipherMode.ECB,
                iv: null,
                out bytesWritten
            );
        }

        /// <summary>
        ///   Decrypts ciphertext data with the specified padding mode using ECB.
        /// </summary>
        /// <param name="ciphertext">
        ///   The ciphertext data to decrypt.
        /// </param>
        /// <param name="paddingMode">
        ///   The padding mode to use when decrypting the ciphertext data.
        /// </param>
        /// <returns>
        ///   The plaintext data, decrypted with the <c>Key</c>.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   Thrown when <paramref name="ciphertext" /> is <c>null</c>.
        /// </exception>
        public byte[] DecryptEcb(byte[] ciphertext, PaddingMode paddingMode)
        {
            if (ciphertext is null)
                throw new ArgumentNullException(nameof(ciphertext));

            return DecryptEcb(ciphertext.AsSpan(), paddingMode);
        }

        /// <summary>
        ///   Decrypts ciphertext data with the specified padding mode using ECB.
        /// </summary>
        /// <param name="ciphertext">
        ///   The ciphertext data to decrypt.
        /// </param>
        /// <param name="paddingMode">
        ///   The padding mode to use when decrypting the ciphertext data.
        /// </param>
        /// <returns>
        ///   The plaintext data, decrypted with the <c>Key</c>.
        /// </returns>
        public byte[] DecryptEcb(ReadOnlySpan<byte> ciphertext, PaddingMode paddingMode)
        {
            byte[] buffer = new byte[ciphertext.Length];

            if (!TryDecryptEcb(ciphertext, buffer, paddingMode, out int plaintextLength))
            {
                Debug.Fail("Allocated buffer is too small.");
                throw new CryptographicException(SR.Argument_BufferTooSmall);
            }

            if (buffer.Length != plaintextLength)
            {
                return buffer[..plaintextLength];
            }
            else
            {
                return buffer;
            }
        }

        /// <summary>
        ///   Decrypts ciphertext data with the specified padding mode using ECB,
        ///   writing the plaintext to a destination buffer.
        /// </summary>
        /// <param name="ciphertext">
        ///   The ciphertext data to decrypt.
        /// </param>
        /// <param name="destination">
        ///   The destination buffer to write the plaintext, decrypted with
        ///   the <c>Key</c>.
        /// </param>
        /// <param name="paddingMode">
        ///   The padding mode to use when decrypting the plaintext data.
        /// </param>
        /// <returns>
        ///   The number of bytes written to <paramref name="destination" />.
        /// </returns>
        /// <exception cref="CryptographicException">
        ///   Thrown when the <paramref name="destination" /> buffer is too small.
        /// </exception>
        public int DecryptEcb(
            ReadOnlySpan<byte> ciphertext,
            Span<byte> destination,
            PaddingMode paddingMode
        )
        {
            if (!TryDecryptEcb(ciphertext, destination, paddingMode, out int bytesWritten))
            {
                throw new CryptographicException(SR.Argument_BufferTooSmall);
            }

            return bytesWritten;
        }

        /// <summary>
        ///   Decrypts ciphertext data with the specified padding mode using ECB,
        ///   writing the plaintext to a destination buffer.
        /// </summary>
        /// <param name="ciphertext">
        ///   The ciphertext data to decrypt.
        /// </param>
        /// <param name="destination">
        ///   The destination buffer to write the plaintext, decrypted with
        ///   the <c>Key</c>.
        /// </param>
        /// <param name="paddingMode">
        ///   The padding mode to use when decrypting the plaintext data.
        /// </param>
        /// <param name="bytesWritten">
        ///   Outputs the number of bytes written to <paramref name="destination" />.
        /// </param>
        /// <returns>
        ///   True if the operation succeeded, otherwise false.
        /// </returns>
        public bool TryDecryptEcb(
            ReadOnlySpan<byte> ciphertext,
            Span<byte> destination,
            PaddingMode paddingMode,
            out int bytesWritten
        ) =>
            TryDecryptEcbCore(ciphertext, destination, paddingMode, out bytesWritten);

        /// <summary>
        ///   The base implementation for <c>DecryptEcb</c> and <c>TryDecryptEcb</c>.
        /// </summary>
        /// <param name="ciphertext">
        ///   The ciphertext data to decrypt.
        /// </param>
        /// <param name="destination">
        ///   The destination buffer to write the plaintext, decrypted with
        ///   the <c>Key</c>.
        /// </param>
        /// <param name="paddingMode">
        ///   The padding mode to use when decrypting the plaintext data.
        /// </param>
        /// <param name="bytesWritten">
        ///   Outputs the number of bytes written to <paramref name="destination" />.
        /// </param>
        /// <returns>
        ///   True if the operation succeeded, otherwise false.
        /// </returns>
        /// <remarks>
        ///   Derived classes should override this to provide a purpose-built implementation
        ///   of ECB decryption. Otherwise, a generic implementation is provided using
        ///   <see cref="CreateDecryptor()" />.
        /// </remarks>
        protected virtual bool TryDecryptEcbCore(
            ReadOnlySpan<byte> ciphertext,
            Span<byte> destination,
            PaddingMode paddingMode,
            out int bytesWritten
        )
        {
            return TryTransformInternal(
                ciphertext,
                destination,
                paddingMode,
                encrypt: false,
                CipherMode.ECB,
                iv: null,
                out bytesWritten
            );
        }

        private bool TryTransformInternal(
            ReadOnlySpan<byte> input,
            Span<byte> output,
            PaddingMode paddingMode,
            bool encrypt,
            CipherMode requiredMode,
            byte[]? iv,
            out int bytesWritten
        )
        {
            if (Mode != requiredMode)
                throw new CryptographicException(SR.Cryptography_UnsupportedCipherModeMismatch);
            if (paddingMode != Padding)
                throw new CryptographicException(SR.Cryptography_UnsupportedPaddingModeMismatch);

            bytesWritten = 0;

            using ICryptoTransform transform = encrypt ? CreateEncryptor(Key, iv) : CreateDecryptor(Key, iv);
            Span<byte> availableOutput = output;
            ReadOnlySpan<byte> remainingInput = input;
            int inputBlockSize = transform.InputBlockSize;
            int outputBlockSize = transform.OutputBlockSize;
            byte[] inputBuffer = CryptoPool.Rent(inputBlockSize);
            byte[] outputBuffer = CryptoPool.Rent(outputBlockSize);

            try
            {
                while (remainingInput.Length > inputBlockSize)
                {
                    remainingInput[..inputBlockSize].CopyTo(inputBuffer);
                    int written = transform.TransformBlock(inputBuffer, 0, inputBlockSize, outputBuffer, 0);

                    if (written > availableOutput.Length)
                    {
                        bytesWritten = 0;
                        return false;
                    }

                    outputBuffer.AsSpan(..written).CopyTo(availableOutput);
                    availableOutput = availableOutput[written..];
                    remainingInput = remainingInput[inputBlockSize..];
                    bytesWritten += written;
                }

                Debug.Assert(remainingInput.Length <= inputBlockSize, $"{remainingInput.Length} <= {inputBlockSize} failed.");
                remainingInput.CopyTo(inputBuffer);
                byte[] final = transform.TransformFinalBlock(inputBuffer, 0, remainingInput.Length);

                if (final.Length > availableOutput.Length)
                {
                    bytesWritten = 0;
                    return false;
                }

                final.CopyTo(availableOutput);
                bytesWritten += final.Length;
                return true;
            }

            finally
            {
                CryptoPool.Return(inputBuffer);
                CryptoPool.Return(outputBuffer);
            }
        }

        protected CipherMode ModeValue;
        protected PaddingMode PaddingValue;
        protected byte[]? KeyValue;
        protected byte[]? IVValue;
        protected int BlockSizeValue;
        protected int FeedbackSizeValue;
        protected int KeySizeValue;
        [MaybeNull] protected KeySizes[] LegalBlockSizesValue = null!;
        [MaybeNull] protected KeySizes[] LegalKeySizesValue = null!;
    }
}
