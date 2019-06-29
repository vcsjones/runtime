// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Internal.Cryptography;

namespace System.Security.Cryptography
{
    public sealed partial class AesGcm : IDisposable
    {
        public static KeySizes NonceByteSizes { get; } = AesGcmPal.NonceByteSizes;
        public static KeySizes TagByteSizes { get; } = AesGcmPal.TagByteSizes;

        private readonly AesGcmPal _pal = AesGcmPal.Create();

        public AesGcm(ReadOnlySpan<byte> key)
        {
            AesAEAD.CheckKeySize(key.Length * 8);
            _pal.ImportKey(key);
        }

        public AesGcm(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            AesAEAD.CheckKeySize(key.Length * 8);
            _pal.ImportKey(key);
        }

        public void Encrypt(byte[] nonce, byte[] plaintext, byte[] ciphertext, byte[] tag, byte[] associatedData = null)
        {
            AesAEAD.CheckArgumentsForNull(nonce, plaintext, ciphertext, tag);
            Encrypt((ReadOnlySpan<byte>)nonce, plaintext, ciphertext, tag, associatedData);
        }

        public void Encrypt(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            Span<byte> tag,
            ReadOnlySpan<byte> associatedData = default)
        {
            CheckParameters(plaintext, ciphertext, nonce, tag);
            _pal.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
        }

        public void Decrypt(byte[] nonce, byte[] ciphertext, byte[] tag, byte[] plaintext, byte[] associatedData = null)
        {
            AesAEAD.CheckArgumentsForNull(nonce, plaintext, ciphertext, tag);
            Decrypt((ReadOnlySpan<byte>)nonce, ciphertext, tag, plaintext, associatedData);
        }

        public void Decrypt(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> tag,
            Span<byte> plaintext,
            ReadOnlySpan<byte> associatedData = default)
        {
            CheckParameters(plaintext, ciphertext, nonce, tag);
            _pal.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
        }

        private static void CheckParameters(
            ReadOnlySpan<byte> plaintext,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> tag)
        {
            if (plaintext.Length != ciphertext.Length)
                throw new ArgumentException(SR.Cryptography_PlaintextCiphertextLengthMismatch);

            if (!nonce.Length.IsLegalSize(NonceByteSizes))
                throw new ArgumentException(SR.Cryptography_InvalidNonceLength, nameof(nonce));

            if (!tag.Length.IsLegalSize(TagByteSizes))
                throw new ArgumentException(SR.Cryptography_InvalidTagLength, nameof(tag));
        }

        public void Dispose()
        {
            _pal.Dispose();
        }
    }
}
