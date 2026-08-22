// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.Pkcs.Asn1;

namespace Internal.Cryptography.Pal.AnyOS
{
    internal sealed partial class ManagedPkcsPal
    {
        internal sealed class ManagedKemPal : KemRecipientInfoPal
        {
            private readonly KemRecipientInfoAsn _asn;

            internal ManagedKemPal(KemRecipientInfoAsn asn)
            {
                _asn = asn;
            }

            public override byte[] EncryptedKey => _asn.EncryptedKey.ToArray();

            public override AlgorithmIdentifier KeyEncapsulationAlgorithm =>
                _asn.Kem.ToPresentationObject();

            public override ReadOnlyMemory<byte> KeyEncapsulationCiphertext => _asn.Kemct;

            public override AlgorithmIdentifier KeyDerivationAlgorithm =>
                _asn.Kdf.ToPresentationObject();

            public override AlgorithmIdentifier KeyEncryptionAlgorithm =>
                _asn.Wrap.ToPresentationObject();

            public override int KeyEncryptionKeyLengthInBytes => _asn.KekLength;

            public override SubjectIdentifier RecipientIdentifier =>
                new SubjectIdentifier(_asn.Rid.IssuerAndSerialNumber, _asn.Rid.SubjectKeyIdentifier);

            public override ReadOnlyMemory<byte>? UserKeyingMaterial => _asn.Ukm;

            public override int Version => _asn.Version;
        }
    }
}
