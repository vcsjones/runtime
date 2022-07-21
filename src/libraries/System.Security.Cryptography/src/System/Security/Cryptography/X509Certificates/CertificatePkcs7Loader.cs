// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Security.Cryptography.Asn1.Pkcs7;
using System.Security.Cryptography.X509Certificates.Asn1;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography.X509Certificates
{
    internal static class CertificatePkcs7Loader<TPal> where TPal : ICertificatePalBlob
    {
        internal static unsafe ICertificatePal LoadPkcs7(ReadOnlySpan<byte> rawData, X509KeyStorageFlags keyStorageFlags)
        {
            fixed (byte* pRawData = rawData)
            using (PointerMemoryManager<byte> manager = new PointerMemoryManager<byte>(pRawData, rawData.Length))
            {
                AsnValueReader reader = new AsnValueReader(rawData, AsnEncodingRules.BER);
                ContentInfoAsn.Decode(ref reader, manager.Memory, out ContentInfoAsn contentInfo);

                switch (contentInfo.ContentType)
                {
                    case Oids.Pkcs7Signed:
                        return FindPkcs7SignedCertificate(contentInfo.Content);
                    default:
                        throw new CryptographicException("TODO");
                }
            }
        }

        private static ICertificatePal FindPkcs7SignedCertificate(ReadOnlyMemory<byte> content)
        {
            SignedDataAsn signedData = SignedDataAsn.Decode(content, AsnEncodingRules.BER);

            if (signedData.SignerInfos.Length == 0 || signedData.CertificateSet is not { Length: > 0 })
            {
                throw new CryptographicException("TODO: CRYPT_E_NO_SIGNER");
            }

            // Match Window's behavior by only examining the first SignerInfo.
            SignerInfoAsn signerInfo = signedData.SignerInfos[0];
            SignerIdentifierAsn signerIdentifier = signerInfo.Sid;

            // RFC 5652:
            // If the SignerIdentifier is the CHOICE issuerAndSerialNumber, then the version MUST be 1.
            // If the SignerIdentifier is subjectKeyIdentifier, then the version MUST be 3.
            if ((signerIdentifier.SubjectKeyIdentifier is not null && signerInfo.Version != 3) ||
                (signerIdentifier.IssuerAndSerialNumber is not null && signerInfo.Version != 1))
            {
                throw new CryptographicException("TODO: INVALID CMS");
            }

            List<X509Certificate2> candidates = new List<X509Certificate2>(signedData.CertificateSet.Length);

            foreach (CertificateChoiceAsn certChoice in signedData.CertificateSet)
            {
                if (!certChoice.Certificate.HasValue)
                {
                    continue;
                }

                try
                {
                    // We want to make sure this is an X.509 certificate DER encoded certificate before passing
                    // it to the X509Certificate2 constructor. The constructor makes a best effort to "figure it out",
                    // but we don't want to permit a CMS/PKCS7 document whose certificate collection contains something
                    // other than a certificate.
                    CertificateAsn.Decode(certChoice.Certificate.Value, AsnEncodingRules.DER);
                }
                catch (CryptographicException)
                {
                    // Ignore non-X.509 certificates.
                    continue;
                }

                candidates.Add(new X509Certificate2(certChoice.Certificate.Value.Span));
            }

            try
            {
                return TryFindMatchingCertificate(candidates, signerIdentifier) ??
                    throw new CryptographicException("TODO: CRYPT_E_NO_SIGNER");
            }
            finally
            {
                foreach (X509Certificate2 cert in candidates)
                {
                    cert.Dispose();
                }
            }
        }

        internal static ICertificatePal? TryFindMatchingCertificate(List<X509Certificate2> certs, SignerIdentifierAsn signerIdentifier)
        {
            // We don't care about the "CN=Dummy Signer" "No signature" case here.

            if (signerIdentifier.IssuerAndSerialNumber is IssuerAndSerialNumberAsn issuerAndSerialNumber)
            {
                ReadOnlySpan<byte> issuer = issuerAndSerialNumber.Issuer.Span;
                ReadOnlySpan<byte> serial = issuerAndSerialNumber.SerialNumber.Span;

                foreach (X509Certificate2 cert in certs)
                {
                    ReadOnlySpan<byte> candidateSerial = cert.SerialNumberBytes.Span;
                    ReadOnlySpan<byte> candidateIssuer = cert.IssuerName.RawData;

                    if (issuer.SequenceEqual(candidateIssuer) && serial.SequenceEqual(candidateSerial))
                    {
                        return TPal.FromOtherCert(cert);
                    }
                }

                return null;
            }
            else if (signerIdentifier.SubjectKeyIdentifier is ReadOnlyMemory<byte> subjectKeyIdentifier)
            {
                foreach (X509Certificate2 cert in certs)
                {
                    X509SubjectKeyIdentifierExtension? ext = cert.Extensions[Oids.SubjectKeyIdentifier] as X509SubjectKeyIdentifierExtension;

                    if (ext is null)
                    {
                        continue;
                    }

                    if (subjectKeyIdentifier.Span.SequenceEqual(ext.SubjectKeyIdentifierBytes.Span))
                    {
                        return TPal.FromOtherCert(cert);
                    }
                }

                return null;
            }
            else
            {
                return null;
            }
        }
    }
}
