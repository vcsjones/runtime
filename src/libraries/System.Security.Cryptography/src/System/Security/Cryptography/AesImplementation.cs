// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Internal.Cryptography;
using System.Diagnostics;

namespace System.Security.Cryptography
{
    internal sealed partial class AesImplementation : Aes
    {
        private ILiteSymmetricCipher? _encryptCbcOneShot;
        private ILiteSymmetricCipher? _decryptCbcOneShot;
        private ILiteSymmetricCipher? _encryptEcbOneShot;
        private ILiteSymmetricCipher? _decryptEcbOneShot;
        private (ILiteSymmetricCipher Cipher, int feedbackSizeInBits)? _decryptCfbOneShot;
        private (ILiteSymmetricCipher Cipher, int feedbackSizeInBits)? _encryptCfbOneShot;

        public sealed override ICryptoTransform CreateDecryptor()
        {
            return CreateTransform(Key, IV, encrypting: false);
        }

        public sealed override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV)
        {
            return CreateTransform(rgbKey, rgbIV.CloneByteArray(), encrypting: false);
        }

        public sealed override ICryptoTransform CreateEncryptor()
        {
            return CreateTransform(Key, IV, encrypting: true);
        }

        public sealed override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[]? rgbIV)
        {
            return CreateTransform(rgbKey, rgbIV.CloneByteArray(), encrypting: true);
        }

        public sealed override void GenerateIV()
        {
            IV = RandomNumberGenerator.GetBytes(BlockSize / BitsPerByte);
        }

        public sealed override void GenerateKey()
        {
            Key = RandomNumberGenerator.GetBytes(KeySize / BitsPerByte);
        }

        public override byte[] Key
        {
            set
            {
                DisposeAndInvalidateOneShotCiphers();
                base.Key = value;
            }
        }

        protected sealed override void Dispose(bool disposing)
        {
            if (disposing)
            {
                DisposeAndInvalidateOneShotCiphers();
            }

            base.Dispose(disposing);
        }

        protected override bool TryDecryptEcbCore(
            ReadOnlySpan<byte> ciphertext,
            Span<byte> destination,
            PaddingMode paddingMode,
            out int bytesWritten)
        {
            if (_decryptEcbOneShot is null)
            {
                _decryptEcbOneShot = CreateLiteCipher(
                    CipherMode.ECB,
                    Key,
                    iv: default,
                    blockSize: BlockSize / BitsPerByte,
                    paddingSize: BlockSize / BitsPerByte,
                    0, /*feedback size */
                    encrypting: false);
            }
            else
            {
                Debug.Assert(_decryptEcbOneShot.SupportsReset);
                _decryptEcbOneShot.Reset(iv: default);
            }

            return UniversalCryptoOneShot.OneShotDecrypt(_decryptEcbOneShot, paddingMode, ciphertext, destination, out bytesWritten);
        }

        protected override bool TryEncryptEcbCore(
            ReadOnlySpan<byte> plaintext,
            Span<byte> destination,
            PaddingMode paddingMode,
            out int bytesWritten)
        {
            if (_encryptEcbOneShot is null)
            {
                _encryptEcbOneShot = CreateLiteCipher(
                    CipherMode.ECB,
                    Key,
                    iv: default,
                    blockSize: BlockSize / BitsPerByte,
                    paddingSize: BlockSize / BitsPerByte,
                    0, /*feedback size */
                    encrypting: true);
            }
            else
            {
                Debug.Assert(_encryptEcbOneShot.SupportsReset);
                _encryptEcbOneShot.Reset(iv: default);
            }

            return UniversalCryptoOneShot.OneShotEncrypt(_encryptEcbOneShot, paddingMode, plaintext, destination, out bytesWritten);
        }

        protected override bool TryEncryptCbcCore(
            ReadOnlySpan<byte> plaintext,
            ReadOnlySpan<byte> iv,
            Span<byte> destination,
            PaddingMode paddingMode,
            out int bytesWritten)
        {
            if (_encryptCbcOneShot is null)
            {
                _encryptCbcOneShot = CreateLiteCipher(
                    CipherMode.CBC,
                    Key,
                    iv,
                    blockSize: BlockSize / BitsPerByte,
                    paddingSize: BlockSize / BitsPerByte,
                    0, /*feedback size */
                    encrypting: true);
            }
            else
            {
                Debug.Assert(_encryptCbcOneShot.SupportsReset);
                _encryptCbcOneShot.Reset(iv);
            }

            return UniversalCryptoOneShot.OneShotEncrypt(_encryptCbcOneShot, paddingMode, plaintext, destination, out bytesWritten);
        }

        protected override bool TryDecryptCbcCore(
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> iv,
            Span<byte> destination,
            PaddingMode paddingMode,
            out int bytesWritten)
        {
            if (_decryptCbcOneShot is null)
            {
                _decryptCbcOneShot = CreateLiteCipher(
                    CipherMode.CBC,
                    Key,
                    iv,
                    blockSize: BlockSize / BitsPerByte,
                    paddingSize: BlockSize / BitsPerByte,
                    0, /*feedback size */
                    encrypting: false);
            }
            else
            {
                Debug.Assert(_decryptCbcOneShot.SupportsReset);
                _decryptCbcOneShot.Reset(iv);
            }

            return UniversalCryptoOneShot.OneShotDecrypt(_decryptCbcOneShot, paddingMode, ciphertext, destination, out bytesWritten);
        }

        protected override bool TryDecryptCfbCore(
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> iv,
            Span<byte> destination,
            PaddingMode paddingMode,
            int feedbackSizeInBits,
            out int bytesWritten)
        {
            ValidateCFBFeedbackSize(feedbackSizeInBits);

            ILiteSymmetricCipher? cipher = null;

            if (_decryptCfbOneShot is (ILiteSymmetricCipher cacheCipher, int size))
            {
                if (size != feedbackSizeInBits)
                {
                    cacheCipher.Dispose();
                }
                else
                {
                    // If it was cached, it should support resetting.
                    Debug.Assert(cacheCipher.SupportsReset);
                    cacheCipher.Reset(iv);
                    cipher = cacheCipher;
                }
            }

            cipher ??= CreateLiteCipher(
                CipherMode.CFB,
                Key,
                iv: iv,
                blockSize: BlockSize / BitsPerByte,
                paddingSize: feedbackSizeInBits / BitsPerByte,
                feedbackSizeInBits / BitsPerByte,
                encrypting: false);

            if (cipher.SupportsReset)
            {
                _decryptCfbOneShot = (cipher, feedbackSizeInBits);
                return UniversalCryptoOneShot.OneShotDecrypt(cipher, paddingMode, ciphertext, destination, out bytesWritten);
            }
            else
            {
                using (cipher)
                {
                    return UniversalCryptoOneShot.OneShotDecrypt(cipher, paddingMode, ciphertext, destination, out bytesWritten);
                }
            }
        }

        protected override bool TryEncryptCfbCore(
            ReadOnlySpan<byte> plaintext,
            ReadOnlySpan<byte> iv,
            Span<byte> destination,
            PaddingMode paddingMode,
            int feedbackSizeInBits,
            out int bytesWritten)
        {
            ValidateCFBFeedbackSize(feedbackSizeInBits);

            ILiteSymmetricCipher? cipher = null;

            if (_encryptCfbOneShot is (ILiteSymmetricCipher cacheCipher, int size))
            {
                if (size != feedbackSizeInBits)
                {
                    cacheCipher.Dispose();
                }
                else
                {
                    Debug.Assert(cacheCipher.SupportsReset);
                    cacheCipher.Reset(iv);
                    cipher = cacheCipher;
                }
            }

            cipher ??= CreateLiteCipher(
                CipherMode.CFB,
                Key,
                iv: iv,
                blockSize: BlockSize / BitsPerByte,
                paddingSize: feedbackSizeInBits / BitsPerByte,
                feedbackSizeInBits / BitsPerByte,
                encrypting: true);

            if (cipher.SupportsReset)
            {
                _encryptCfbOneShot = (cipher, feedbackSizeInBits);
                return UniversalCryptoOneShot.OneShotEncrypt(cipher, paddingMode, plaintext, destination, out bytesWritten);
            }
            else
            {
                using (cipher)
                {
                    return UniversalCryptoOneShot.OneShotEncrypt(cipher, paddingMode, plaintext, destination, out bytesWritten);
                }
            }
        }

        private ICryptoTransform CreateTransform(byte[] rgbKey, byte[]? rgbIV, bool encrypting)
        {
            // note: rbgIV is guaranteed to be cloned before this method, so no need to clone it again

            if (rgbKey == null)
                throw new ArgumentNullException(nameof(rgbKey));

            long keySize = rgbKey.Length * (long)BitsPerByte;
            if (keySize > int.MaxValue || !((int)keySize).IsLegalSize(this.LegalKeySizes))
                throw new ArgumentException(SR.Cryptography_InvalidKeySize, nameof(rgbKey));

            if (rgbIV != null)
            {
                long ivSize = rgbIV.Length * (long)BitsPerByte;
                if (ivSize != BlockSize)
                    throw new ArgumentException(SR.Cryptography_InvalidIVSize, nameof(rgbIV));
            }

            if (Mode == CipherMode.CFB)
            {
                ValidateCFBFeedbackSize(FeedbackSize);
            }

            return CreateTransformCore(
                Mode,
                Padding,
                rgbKey,
                rgbIV,
                BlockSize / BitsPerByte,
                this.GetPaddingSize(Mode, FeedbackSize),
                FeedbackSize / BitsPerByte,
                encrypting);
        }

        private static void ValidateCFBFeedbackSize(int feedback)
        {
            // only 8bits/128bits feedback would be valid.
            if (feedback != 8 && feedback != 128)
            {
                throw new CryptographicException(string.Format(SR.Cryptography_CipherModeFeedbackNotSupported, feedback, CipherMode.CFB));
            }
        }

        private void DisposeAndInvalidateOneShotCiphers()
        {
            _decryptCbcOneShot?.Dispose();
            _decryptCbcOneShot = null;
            _encryptCbcOneShot?.Dispose();
            _encryptCbcOneShot = null;
            _decryptEcbOneShot?.Dispose();
            _decryptEcbOneShot = null;
            _encryptEcbOneShot?.Dispose();
            _encryptEcbOneShot = null;
            _decryptCfbOneShot?.Cipher.Dispose();
            _decryptCfbOneShot = null;
            _encryptCfbOneShot?.Cipher.Dispose();
            _encryptCfbOneShot = null;
        }

        private const int BitsPerByte = 8;
    }
}
