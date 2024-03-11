// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Formats.Asn1;
using System.Security.Cryptography.Asn1.Pkcs12;
using System.Security.Cryptography.Asn1.Pkcs7;
using Internal.Cryptography;

namespace System.Security.Cryptography.X509Certificates
{
    public static partial class X509CertificateLoader
    {
        private const int ErrorInvalidPasswordHResult = unchecked((int)0x80070056);

        private static X509Certificate2 LoadPkcs12(
            ReadOnlyMemory<byte> data,
            ReadOnlySpan<char> password,
            X509KeyStorageFlags keyStorageFlags,
            Pkcs12LoaderLimits loaderLimits)
        {
            if (ReferenceEqual(loaderLimits, Pkcs12LoaderLimits.DangerousNoLimits))
            {
                X509Certificate2? earlyReturn = null;
                LoadPkcs12NoLimits(data, password, keyStorageFlags, ref earlyReturn);

                if (earlyReturn is not null)
                {
                    return earlyReturn;
                }
            }

            using (BagState bags = default)
            {
                ReadCertsAndKeys(ref bags, data, password, loaderLimits);

                throw new Exception("Finish writing this");
            }
        }

        private static void ReadCertsAndKeys(
            ref BagState bags,
            ReadOnlyMemory<byte> data,
            ReadOnlySpan<char> password,
            Pkcs12LoaderLimits loaderLimits)
        {
            try
            {
                PfxAsn pfxAsn = PfxAsn.Decode(data, AsnEncodingRules.BER);

                if (pfxAsn.AuthSafe.ContentType != Oids.Pkcs7Data)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                ReadOnlyMemory<byte> authSafeMemory =
                    Helpers.DecodeOctetStringAsMemory(pfxAsn.AuthSafe.Content);
                ReadOnlySpan<byte> authSafeContents = authSafeMemory.Span;
                bool ambiguousPassword = password.IsEmpty;

                if (pfxAsn.MacData.HasValue)
                {
                    if (pfxAsn.MacData.Value.IterationCount > loaderLimits.MacIterationLimit)
                    {
                        throw new Pkcs12LoadLimitExceededException(nameof(Pkcs12LoaderLimits.MacIterationLimit));
                    }

                    bool verified = false;

                    if (ambiguousPassword)
                    {
                        if (!pfxAsn.VerifyMac(password, authSafeContents))
                        {
                            password = password.ContainsNull() ? "" : default;
                        }
                        else
                        {
                            verified = true;
                        }
                    }

                    if (!verified && !pfxAsn.VerifyMac(password, authSafeContents))
                    {
                        throw new CryptographicException(SR.Cryptography_Pfx_BadPassword)
                        {
                            HResult = ErrorInvalidPasswordHResult,
                        };
                    }

                    ambiguousPassword = false;
                }

                AsnValueReader outer = new AsnValueReader(authSafeContents, AsnEncodingRules.BER);
                AsnValueReader reader = outer.ReadSequence();
                outer.ThrowIfNotEmpty();

                ReadOnlyMemory<byte> rebind = pfxAsn.AuthSafe.Content;
                bags.Init(loaderLimits);

                int? workRemaining = loaderLimits.TotalKdfIterationLimit;

                while (reader.HasData)
                {
                    ContentInfoAsn.Decode(ref reader, rebind, out ContentInfoAsn safeContentsAsn);

                    ReadOnlyMemory<byte> contentData;

                    if (safeContentsAsn.ContentType == Oids.Pkcs7Data)
                    {
                        contentData = Helpers.DecodeOctetStringAsMemory(safeContentsAsn.Content);
                    }
                    else if (safeContentsAsn.ContentType == Oids.Pkcs7Encrypted)
                    {
                        if (ambiguousPassword)
                        {
                            ambiguousPassword = false;
                            int? workRemainingSave = workRemaining;

                            try
                            {
                                contentData = DecryptSafeContents(
                                    safeContentsAsn,
                                    loaderLimits,
                                    password,
                                    authSafeContents.Length,
                                    ref decryptBuffer,
                                    ref workRemaining,
                                    ref decryptBufferOffset);

                                try
                                {
                                    AsnValueReader test =
                                        new AsnValueReader(contentData.Span, AsnEncodingRules.BER);

                                    test.ReadSequence();
                                    test.ThrowIfNotEmpty();
                                }
                                catch (AsnContentException)
                                {
                                    throw new CryptographicException();
                                }
                            }
                            catch (CryptographicException)
                            {
                                password = password.ContainsNull() ? "" : default;
                                workRemaining = workRemainingSave;
                                decryptBufferOffset = 0;

//#error why is this here and not above?
                                if (!loaderLimits.AllowMultipleEncryptedSegments &&
                                    decryptBuffer is not null)
                                {
                                    CryptoPool.Return(decryptBuffer);
                                    decryptBuffer = null;
                                }

                                contentData = DecryptSafeContents(
                                    safeContentsAsn,
                                    loaderLimits,
                                    password,
                                    authSafeContents.Length,
                                    ref decryptBuffer,
                                    ref workRemaining,
                                    ref decryptBufferOffset);
                            }
                        }
                        else
                        {
                            contentData = DecryptSafeContents(
                                safeContentsAsn,
                                loaderLimits,
                                password,
                                authSafeContents.Length,
                                ref decryptBuffer,
                                ref workRemaining,
                                ref decryptBufferOffset);
                        }
                    }
                    else
                    {
                        // Should there be an option here to preserve this?
                        // Ignore this?
                        throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                    }

                    ProcessSafeContents(
                        contentData,
                        loaderLimits,
                        ref workRemaining,
                        ref certBags,
                        ref certBagIdx,
                        ref keyBags,
                        ref keyBagIdx);
                }
            }
            catch (AsnContentException e)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding, e);
            }
        }

        private struct BagState : IDisposable
        {
            private SafeBagAsn[]? _certBags;
            private SafeBagAsn[]? _keyBags;
            private int _certCount;
            private int _keyCount;

            internal void Init(Pkcs12LoaderLimits loaderLimits)
            {
                _certBags = ArrayPool<SafeBagAsn>.Shared.Rent(loaderLimits.MaxCertificates.GetValueOrDefault(10));
                _keyBags = ArrayPool<SafeBagAsn>.Shared.Rent(loaderLimits.MaxKeys.GetValueOrDefault(10));
                _certCount = 0;
                _keyCount = 0;
            }

            public void Dispose()
            {
                if (_certBags is not null)
                {
                    ArrayPool<SafeBagAsn>.Shared.Return(_certBags, clearArray: true);
                }

                if (_certBags is not null)
                {
                    ArrayPool<SafeBagAsn>.Shared.Return(_keyBags, clearArray: true);
                }

                _certBags = _keyBags = null;
                _certCount = _keyCount = 0;
            }
        }
    }
}
