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
        internal KemRecipientInfo(KemRecipientInfoPal pal)
            : base(RecipientInfoType.KeyEncapsulation, pal)
        {
        }

        /// <inheritdoc />
        public override int Version
        {
            get
            {
                return Pal.Version;
            }
        }

        /// <inheritdoc />
        public override SubjectIdentifier RecipientIdentifier
        {
            get
            {
                return _lazyRecipientIdentifier ??= Pal.RecipientIdentifier;
            }
        }

        /// <inheritdoc />
        public override AlgorithmIdentifier KeyEncryptionAlgorithm
        {
            get
            {
                return _lazyKeyEncryptionAlgorithm ??= Pal.KeyEncryptionAlgorithm;
            }
        }

        /// <inheritdoc />
        public override byte[] EncryptedKey
        {
            get
            {
                return _lazyEncryptedKey ??= Pal.EncryptedKey;
            }
        }

        /// <summary>
        /// Gets the key-encapsulation algorithm.
        /// </summary>
        /// <value>The key-encapsulation algorithm identifier.</value>
        public AlgorithmIdentifier KeyEncapsulationAlgorithm
        {
            get
            {
                return _lazyKeyEncapsulationAlgorithm ??= Pal.KeyEncapsulationAlgorithm;
            }
        }

        /// <summary>
        /// Gets the key-encapsulation ciphertext.
        /// </summary>
        /// <value>The key-encapsulation ciphertext.</value>
        public ReadOnlyMemory<byte> KeyEncapsulationCiphertext => Pal.KeyEncapsulationCiphertext;

        /// <summary>
        /// Gets the key-derivation algorithm.
        /// </summary>
        /// <value>The key-derivation algorithm identifier.</value>
        public AlgorithmIdentifier KeyDerivationAlgorithm => Pal.KeyDerivationAlgorithm;

        /// <summary>
        /// Gets the key-encryption key length, in bytes.
        /// </summary>
        /// <value>The key-encryption key length, in bytes.</value>
        public int KeyEncryptionKeyLengthInBytes => Pal.KeyEncryptionKeyLengthInBytes;

        /// <summary>
        /// Gets the user keying material.
        /// </summary>
        /// <value>
        /// The user keying material, or <see langword="null" /> if the optional value was not present.
        /// An empty value indicates that the optional value was present with a length of zero.
        /// </value>
        public ReadOnlyMemory<byte>? UserKeyingMaterial => Pal.UserKeyingMaterial;

        private new KemRecipientInfoPal Pal
        {
            get
            {
                return (KemRecipientInfoPal)base.Pal;
            }
        }

        private SubjectIdentifier? _lazyRecipientIdentifier;
        private AlgorithmIdentifier? _lazyKeyEncryptionAlgorithm;
        private byte[]? _lazyEncryptedKey;
        private AlgorithmIdentifier? _lazyKeyEncapsulationAlgorithm;
    }
}
