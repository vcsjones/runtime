// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;

using Internal.Cryptography;

namespace System.Security.Cryptography.Pkcs
{
    public sealed partial class EnvelopedCms
    {
        /// <summary>
        /// Decrypts the content using the specified key-encapsulation recipient information and ML-KEM private key.
        /// </summary>
        /// <param name="recipientInfo">The recipient information to use for decrypting the content.</param>
        /// <param name="privateKey">The ML-KEM private key to use for decrypting the content.</param>
        public void Decrypt(KemRecipientInfo recipientInfo, MLKem privateKey)
        {
            ArgumentNullException.ThrowIfNull(recipientInfo);
            ArgumentNullException.ThrowIfNull(privateKey);

            CheckStateForDecryption();

            X509Certificates.X509Certificate2Collection extraStore = new X509Certificates.X509Certificate2Collection();
            ContentInfo? contentInfo = _decryptorPal!.TryDecrypt(
                recipientInfo,
                null,
                privateKey,
                Certificates,
                extraStore,
                out Exception? exception);

            if (exception is not null)
            {
                throw exception;
            }

            SetContentInfo(contentInfo!);
        }
    }
}
