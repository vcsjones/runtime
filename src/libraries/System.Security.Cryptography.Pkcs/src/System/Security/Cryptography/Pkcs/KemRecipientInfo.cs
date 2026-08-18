// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;

using Internal.Cryptography;

namespace System.Security.Cryptography.Pkcs
{
    /// <summary>
    /// Represents recipient information that uses a key-encapsulation mechanism (KEM).
    /// </summary>
    public sealed class KemRecipientInfo : RecipientInfo
    {
        internal KemRecipientInfo()
            : base(RecipientInfoType.KeyEncapsulation, ThrowNotImplemented())
        {
        }

        /// <inheritdoc />
        public override int Version => throw new NotImplementedException();

        /// <inheritdoc />
        public override SubjectIdentifier RecipientIdentifier => throw new NotImplementedException();

        /// <inheritdoc />
        public override AlgorithmIdentifier KeyEncryptionAlgorithm => throw new NotImplementedException();

        /// <inheritdoc />
        public override byte[] EncryptedKey => throw new NotImplementedException();

        /// <summary>
        /// Gets the key-encapsulation algorithm.
        /// </summary>
        /// <value>The key-encapsulation algorithm identifier.</value>
        public AlgorithmIdentifier KeyEncapsulationAlgorithm => throw new NotImplementedException();

        /// <summary>
        /// Gets the key-encapsulation ciphertext.
        /// </summary>
        /// <value>The key-encapsulation ciphertext.</value>
        public ReadOnlyMemory<byte> KeyEncapsulationCiphertext => throw new NotImplementedException();

        /// <summary>
        /// Gets the key-derivation algorithm.
        /// </summary>
        /// <value>The key-derivation algorithm identifier.</value>
        public AlgorithmIdentifier KeyDerivationAlgorithm => throw new NotImplementedException();

        /// <summary>
        /// Gets the key-encryption key length, in bytes.
        /// </summary>
        /// <value>The key-encryption key length, in bytes.</value>
        public int KeyEncryptionKeyLengthInBytes => throw new NotImplementedException();

        /// <summary>
        /// Gets the user keying material.
        /// </summary>
        /// <value>
        /// The user keying material, or <see langword="null" /> if the optional value was not present.
        /// An empty value indicates that the optional value was present with a length of zero.
        /// </value>
        public ReadOnlyMemory<byte>? UserKeyingMaterial => throw new NotImplementedException();

        private static RecipientInfoPal ThrowNotImplemented() => throw new NotImplementedException();
    }
}
