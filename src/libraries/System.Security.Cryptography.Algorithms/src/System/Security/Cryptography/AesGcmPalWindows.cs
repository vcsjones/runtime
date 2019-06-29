// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Internal.Cryptography;
using Internal.NativeCrypto;

namespace System.Security.Cryptography
{
    internal sealed class AesGcmPalWindows : AesGcmPal
    {
        private static readonly SafeAlgorithmHandle s_aesGcm = AesBCryptModes.OpenAesAlgorithm(Cng.BCRYPT_CHAIN_MODE_GCM);
        private SafeKeyHandle _keyHandle;

        public override void ImportKey(ReadOnlySpan<byte> key)
        {
            _keyHandle = s_aesGcm.BCryptImportKey(key);
        }

        public override void Encrypt(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            Span<byte> tag,
            ReadOnlySpan<byte> associatedData = default)
        {
            AesAEAD.Encrypt(s_aesGcm, _keyHandle, nonce, associatedData, plaintext, ciphertext, tag);
        }

        public override void Decrypt(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> tag,
            Span<byte> plaintext,
            ReadOnlySpan<byte> associatedData = default)
        {
            AesAEAD.Decrypt(s_aesGcm, _keyHandle, nonce, associatedData, ciphertext, tag, plaintext, clearPlaintextOnFailure: true);
        }

        public override void Dispose()
        {
            _keyHandle.Dispose();
        }
    }
}
