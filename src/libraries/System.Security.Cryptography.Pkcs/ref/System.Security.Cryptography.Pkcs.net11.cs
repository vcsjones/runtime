// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// ------------------------------------------------------------------------------
// Changes to this file must follow the https://aka.ms/api-review process.
// ------------------------------------------------------------------------------

namespace System.Security.Cryptography.Pkcs
{
    public sealed partial class CmsRecipient
    {
        public static System.Security.Cryptography.Pkcs.CmsRecipient CreateForKeyEncapsulation(System.Security.Cryptography.Pkcs.SubjectIdentifierType recipientIdentifierType, System.Security.Cryptography.X509Certificates.X509Certificate2 certificate, System.ReadOnlySpan<byte> userKeyingMaterial) { throw null; }
        public static System.Security.Cryptography.Pkcs.CmsRecipient CreateForKeyEncapsulation(System.Security.Cryptography.X509Certificates.X509Certificate2 certificate, System.ReadOnlySpan<byte> userKeyingMaterial) { throw null; }
    }
    public sealed partial class EnvelopedCms
    {
        public void Decrypt(System.Security.Cryptography.Pkcs.KemRecipientInfo recipientInfo, System.Security.Cryptography.MLKem privateKey) { }
    }
    public sealed partial class KemRecipientInfo : System.Security.Cryptography.Pkcs.RecipientInfo
    {
        internal KemRecipientInfo() { }
        public override byte[] EncryptedKey { get { throw null; } }
        public System.Security.Cryptography.Pkcs.AlgorithmIdentifier KeyDerivationAlgorithm { get { throw null; } }
        public System.Security.Cryptography.Pkcs.AlgorithmIdentifier KeyEncapsulationAlgorithm { get { throw null; } }
        public System.ReadOnlyMemory<byte> KeyEncapsulationCiphertext { get { throw null; } }
        public override System.Security.Cryptography.Pkcs.AlgorithmIdentifier KeyEncryptionAlgorithm { get { throw null; } }
        public int KeyEncryptionKeyLengthInBytes { get { throw null; } }
        public override System.Security.Cryptography.Pkcs.SubjectIdentifier RecipientIdentifier { get { throw null; } }
        public System.ReadOnlyMemory<byte>? UserKeyingMaterial { get { throw null; } }
        public override int Version { get { throw null; } }
    }
}
