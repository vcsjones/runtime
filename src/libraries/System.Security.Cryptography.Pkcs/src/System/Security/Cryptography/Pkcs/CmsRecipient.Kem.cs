// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Security.Cryptography.X509Certificates;

namespace System.Security.Cryptography.Pkcs
{
    public sealed partial class CmsRecipient
    {
        /// <summary>
        /// Creates a recipient for key encapsulation using the specified certificate and user keying material.
        /// </summary>
        /// <param name="certificate">The certificate that identifies the recipient.</param>
        /// <param name="userKeyingMaterial">The user keying material, which can be empty.</param>
        /// <returns>A recipient configured for key encapsulation.</returns>
        public static CmsRecipient CreateForKeyEncapsulation(
            X509Certificate2 certificate,
            ReadOnlySpan<byte> userKeyingMaterial) =>
            CreateForKeyEncapsulation(
                SubjectIdentifierType.IssuerAndSerialNumber,
                certificate,
                userKeyingMaterial);

        /// <summary>
        /// Creates a recipient for key encapsulation using the specified recipient identifier type, certificate, and user keying material.
        /// </summary>
        /// <param name="recipientIdentifierType">One of the enumeration values that specifies the recipient identifier type.</param>
        /// <param name="certificate">The certificate that identifies the recipient.</param>
        /// <param name="userKeyingMaterial">The user keying material, which can be empty.</param>
        /// <returns>A recipient configured for key encapsulation.</returns>
        public static CmsRecipient CreateForKeyEncapsulation(
            SubjectIdentifierType recipientIdentifierType,
            X509Certificate2 certificate,
            ReadOnlySpan<byte> userKeyingMaterial)
        {
            CmsRecipient recipient = new CmsRecipient(recipientIdentifierType, certificate);

            if (!recipient.IsKeyEncapsulation)
            {
                throw new CryptographicException(SR.Cryptography_Cms_Recipient_MLKEMRequired);
            }

            recipient.KeyEncapsulationUserKeyingMaterial = userKeyingMaterial.ToArray();
            return recipient;
        }

        internal bool IsKeyEncapsulation =>
            Certificate.GetKeyAlgorithm() is Oids.MlKem512 or Oids.MlKem768 or Oids.MlKem1024;

        internal byte[]? KeyEncapsulationUserKeyingMaterial { get; private set; }
    }
}
