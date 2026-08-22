// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.Pkcs.Asn1;
using System.Security.Cryptography.X509Certificates;

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

            internal byte[]? DecryptCek(X509Certificate2? cert, MLKem? privateKey, out Exception? exception)
            {
                if (privateKey is not null)
                {
                    return DecryptCekCore(privateKey, out exception);
                }

                Debug.Assert(cert is not null);

                using (MLKem? certificateKey = cert.GetMLKemPrivateKey())
                {
                    if (certificateKey is null)
                    {
                        exception = new CryptographicException(SR.Cryptography_Cms_Signing_RequiresPrivateKey);
                        return null;
                    }

                    return DecryptCekCore(certificateKey, out exception);
                }
            }

            private unsafe byte[]? DecryptCekCore(MLKem privateKey, out Exception? exception)
            {
                try
                {
                    MLKemAlgorithm kemAlgorithm = GetKemAlgorithm(_asn.Kem.Algorithm);
                    int kekLength = GetKeyWrapSizeInBytes(_asn.Wrap.Algorithm);
                    HashAlgorithmName kdfHashAlgorithm = GetKdfHashAlgorithm(_asn.Kdf.Algorithm);

                    const int MinimumWrappedKeySize = 24;
                    const int KeyWrapBlockSize = 8;

                    if (_asn.Version != 0 ||
                        privateKey.Algorithm != kemAlgorithm ||
                        _asn.Kem.Parameters is not null ||
                        _asn.Kemct.Length != kemAlgorithm.CiphertextSizeInBytes ||
                        _asn.Kdf.Parameters is not null ||
                        _asn.KekLength != kekLength ||
                        _asn.EncryptedKey.Length < MinimumWrappedKeySize ||
                        _asn.EncryptedKey.Length % KeyWrapBlockSize != 0 ||
                        // TODO-KEM: Support UKM when deriving the key-encryption key.
                        _asn.Ukm.HasValue ||
                        _asn.Wrap.Parameters is not null)
                    {
                        throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                    }

                    const int SharedSecretSize = 32;

                    if (kemAlgorithm.SharedSecretSizeInBytes != SharedSecretSize)
                    {
                        Debug.Fail($"Unexpected ML-KEM shared secret size: {kemAlgorithm.SharedSecretSizeInBytes}.");
                        throw new CryptographicException();
                    }

                    Span<byte> sharedSecret = stackalloc byte[SharedSecretSize];
                    byte[] keyEncryptionKey = new byte[kekLength];

                    fixed (byte* pinnedKeyEncryptionKey = keyEncryptionKey)
                    {
                        try
                        {
                            privateKey.Decapsulate(_asn.Kemct.Span, sharedSecret);

                            ValueCmsOriForKemOtherInfoAsn otherInfo = new ValueCmsOriForKemOtherInfoAsn
                            {
                                Wrap = new ValueAlgorithmIdentifierAsn
                                {
                                    Algorithm = _asn.Wrap.Algorithm,
                                },
                                KekLength = _asn.KekLength,
                                // TODO-KEM: Include UKM after UKM decryption support is implemented.
                            };

                            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
                            otherInfo.Encode(writer);

                            HKDF.DeriveKey(
                                kdfHashAlgorithm,
                                sharedSecret,
                                keyEncryptionKey,
                                ReadOnlySpan<byte>.Empty,
                                writer.Encode());

                            using (Aes aes = Aes.Create())
                            {
                                aes.Key = keyEncryptionKey;
                                exception = null;
                                return aes.DecryptKeyWrap(_asn.EncryptedKey.Span);
                            }
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(sharedSecret);
                            CryptographicOperations.ZeroMemory(keyEncryptionKey);
                        }
                    }
                }
                catch (CryptographicException e)
                {
                    exception = e;
                    return null;
                }
            }

            private static MLKemAlgorithm GetKemAlgorithm(string kemAlgorithm)
            {
                return kemAlgorithm switch
                {
                    Oids.MlKem512 => MLKemAlgorithm.MLKem512,
                    Oids.MlKem768 => MLKemAlgorithm.MLKem768,
                    Oids.MlKem1024 => MLKemAlgorithm.MLKem1024,
                    _ => throw new CryptographicException(
                        SR.Cryptography_Cms_UnknownAlgorithm,
                        kemAlgorithm),
                };
            }

            private static int GetKeyWrapSizeInBytes(string wrapAlgorithm)
            {
                return wrapAlgorithm switch
                {
                    Oids.Aes128Wrap => 16,
                    Oids.Aes192Wrap => 24,
                    Oids.Aes256Wrap => 32,
                    _ => throw new CryptographicException(
                        SR.Cryptography_Cms_UnknownAlgorithm,
                        wrapAlgorithm),
                };
            }

            private static HashAlgorithmName GetKdfHashAlgorithm(string kdfAlgorithm)
            {
                return kdfAlgorithm switch
                {
                    Oids.HkdfWithSha256 => HashAlgorithmName.SHA256,
                    Oids.HkdfWithSha384 => HashAlgorithmName.SHA384,
                    Oids.HkdfWithSha512 => HashAlgorithmName.SHA512,
                    Oids.HkdfWithSha3_256 => HashAlgorithmName.SHA3_256,
                    Oids.HkdfWithSha3_384 => HashAlgorithmName.SHA3_384,
                    Oids.HkdfWithSha3_512 => HashAlgorithmName.SHA3_512,
                    _ => throw new CryptographicException(
                        SR.Cryptography_Cms_UnknownAlgorithm,
                        kdfAlgorithm),
                };
            }
        }
    }
}
