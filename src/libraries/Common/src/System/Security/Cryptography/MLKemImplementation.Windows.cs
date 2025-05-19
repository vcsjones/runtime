// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Text;
using Internal.NativeCrypto;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography
{
    internal sealed partial class MLKemImplementation : MLKem
    {
        private const uint BCRYPT_MLKEM_PUBLIC_MAGIC = 0x504B4C4D; // MLKP
        private const uint BCRYPT_MLKEM_PRIVATE_MAGIC = 0x524B4C4D; // MLKR
        private const uint BCRYPT_MLKEM_PRIVATE_SEED_MAGIC = 0x534B4C4D; // MLKS
        private const string BCRYPT_MLKEM_PRIVATE_SEED_BLOB = "MLKEMPRIVATESEEDBLOB";
        private const string BCRYPT_MLKEM_PRIVATE_BLOB = "MLKEMPRIVATEBLOB";
        private const string BCRYPT_MLKEM_PUBLIC_BLOB = "MLKEMPUBLICBLOB";

        private static readonly SafeBCryptAlgorithmHandle? s_algHandle = GetMLKemAlgorithmHandle();

        [MemberNotNullWhen(true, nameof(s_algHandle))]
        internal static new bool IsSupported =>
#if NET || NETSTANDARD2_0_OR_GREATER
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && s_algHandle is not null;
#elif NETFRAMEWORK
            s_algHandle is not null;
#else
#error Unhandled platform targets
#endif

        private readonly SafeBCryptKeyHandle _key;
        private readonly bool _hasSeed;
        private readonly bool _hasDecapsulationKey;

        private static SafeBCryptAlgorithmHandle? GetMLKemAlgorithmHandle()
        {
            try
            {
                return Interop.BCrypt.BCryptOpenAlgorithmProvider(BCryptNative.AlgorithmName.MLKEM);
            }
            catch (CryptographicException)
            {
                return null;
            }
        }

        private MLKemImplementation(
            MLKemAlgorithm algorithm,
            SafeBCryptKeyHandle key,
            bool hasSeed,
            bool hasDecapsulationKey) : base(algorithm)
        {
            _key = key;
            _hasDecapsulationKey = hasDecapsulationKey;
            _hasSeed = hasSeed;
        }

        internal static MLKemImplementation GenerateKeyImpl(MLKemAlgorithm algorithm)
        {
            Debug.Assert(IsSupported);
            SafeBCryptKeyHandle key = Interop.BCrypt.BCryptGenerateKeyPair(s_algHandle, 0);
            string parameterSet = GetParameterSet(algorithm);
            Cng.BCryptSetProperty(key, Cng.BCRYPT_PARAMETER_SET_NAME, parameterSet, 0);
            Interop.BCrypt.BCryptFinalizeKeyPair(key);
            return new MLKemImplementation(algorithm, key, hasSeed: true, hasDecapsulationKey: true);
        }

        internal static MLKemImplementation ImportPrivateSeedImpl(MLKemAlgorithm algorithm, ReadOnlySpan<byte> source)
        {
            Debug.Assert(IsSupported);
            Debug.Assert(source.Length == algorithm.PrivateSeedSizeInBytes);
            SafeBCryptKeyHandle key = ImportKey(BCRYPT_MLKEM_PRIVATE_SEED_MAGIC, algorithm, source);
            return new MLKemImplementation(algorithm, key, hasSeed: true, hasDecapsulationKey: true);
        }

        internal static MLKemImplementation ImportDecapsulationKeyImpl(MLKemAlgorithm algorithm, ReadOnlySpan<byte> source)
        {
            Debug.Assert(IsSupported);
            Debug.Assert(source.Length == algorithm.DecapsulationKeySizeInBytes);
            SafeBCryptKeyHandle key = ImportKey(BCRYPT_MLKEM_PRIVATE_MAGIC, algorithm, source);
            return new MLKemImplementation(algorithm, key, hasSeed: false, hasDecapsulationKey: true);
        }

        internal static MLKemImplementation ImportEncapsulationKeyImpl(MLKemAlgorithm algorithm, ReadOnlySpan<byte> source)
        {
            Debug.Assert(IsSupported);
            Debug.Assert(source.Length == algorithm.EncapsulationKeySizeInBytes);
            SafeBCryptKeyHandle key = ImportKey(BCRYPT_MLKEM_PUBLIC_MAGIC, algorithm, source);
            return new MLKemImplementation(algorithm, key, hasSeed: false, hasDecapsulationKey: false);
        }

        protected override void DecapsulateCore(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
        {
            uint written = Interop.BCrypt.BCryptDecapsulate(_key, ciphertext, sharedSecret, 0);
            Debug.Assert(written == (uint)sharedSecret.Length);
        }

        protected override void EncapsulateCore(Span<byte> ciphertext, Span<byte> sharedSecret)
        {
            Interop.BCrypt.BCryptEncapsulate(
                _key,
                sharedSecret,
                ciphertext,
                out uint sharedSecretWritten,
                out uint ciphertextWritten,
                0);
            Debug.Assert(sharedSecretWritten == (uint)sharedSecret.Length);
            Debug.Assert(ciphertextWritten == (uint)ciphertext.Length);
        }

        protected override void ExportPrivateSeedCore(Span<byte> destination)
        {
            ExportKey(BCRYPT_MLKEM_PRIVATE_SEED_MAGIC, destination);
        }

        protected override void ExportDecapsulationKeyCore(Span<byte> destination)
        {
            ExportKey(BCRYPT_MLKEM_PRIVATE_MAGIC, destination);
        }

        protected override void ExportEncapsulationKeyCore(Span<byte> destination)
        {
            ExportKey(BCRYPT_MLKEM_PUBLIC_MAGIC, destination);
        }

        protected override bool TryExportPkcs8PrivateKeyCore(Span<byte> destination, out int bytesWritten)
        {
            return MLKemPkcs8.TryExportPkcs8PrivateKey(
                this,
                _hasSeed,
                _hasDecapsulationKey,
                destination,
                out bytesWritten);
        }

        private static string GetParameterSet(MLKemAlgorithm algorithm)
        {
            if (algorithm == MLKemAlgorithm.MLKem512)
            {
                return "512";
            }
            else if (algorithm == MLKemAlgorithm.MLKem768)
            {
                return "768";
            }
            else if (algorithm == MLKemAlgorithm.MLKem1024)
            {
                return "1024";
            }
            else
            {
                Debug.Fail($"Unknown parameter set for '{algorithm.Name}'.");
                throw new CryptographicException();
            }
        }

        private static SafeBCryptKeyHandle ImportKey(uint kind, MLKemAlgorithm algorithm, ReadOnlySpan<byte> key)
        {
            Debug.Assert(IsSupported);
            // ML-KEM 1024 seeds are 86 byte blobs. Round it off to 128.
            // Other keys like encapsulation or decapsulation keys will never fit in a stack buffer, so don't
            // try to accomodate them.
            const int MaxKeyStackSize = 128;
            string parameterSet = GetParameterSet(algorithm);
            int blobHeaderSize = Marshal.SizeOf<BCRYPT_MLKEM_KEY_BLOB>();
            int parameterSetMarshalLength = ((parameterSet.Length + 1) * 2);
            int blobSize =
                blobHeaderSize +
                parameterSetMarshalLength +
                key.Length;

            byte[]? rented = null;
            Span<byte> buffer = (uint)blobSize <= MaxKeyStackSize ?
                stackalloc byte[MaxKeyStackSize] :
                (rented = CryptoPool.Rent(blobSize));

            try
            {
                buffer.Clear();

                unsafe
                {
                    fixed (byte* pBuffer = buffer)
                    {
                        BCRYPT_MLKEM_KEY_BLOB* blob = (BCRYPT_MLKEM_KEY_BLOB*)pBuffer;
                        blob->dwMagic = kind;
                        blob->cbParameterSet = (uint)parameterSetMarshalLength;
                        blob->cbKey = (uint)key.Length;
                    }
                }

                // This won't write the null byte, but we zeroed the whole buffer earlier.
                Encoding.Unicode.GetBytes(parameterSet, buffer.Slice(blobHeaderSize));
                key.CopyTo(buffer.Slice(blobHeaderSize + parameterSetMarshalLength));
                string blobKind = kind switch
                {
                    BCRYPT_MLKEM_PRIVATE_SEED_MAGIC => BCRYPT_MLKEM_PRIVATE_SEED_BLOB,
                    BCRYPT_MLKEM_PRIVATE_MAGIC => BCRYPT_MLKEM_PRIVATE_BLOB,
                    BCRYPT_MLKEM_PUBLIC_MAGIC => BCRYPT_MLKEM_PUBLIC_BLOB,
                    _ => throw Fail(),
                };

                SafeBCryptKeyHandle keyHandle = Interop.BCrypt.BCryptImportKeyPair(
                    s_algHandle,
                    blobKind,
                    buffer.Slice(0, blobSize));

                // WINDOWS BUG? We shouldn't need to finalize imported key pairs.
                Interop.BCrypt.BCryptFinalizeKeyPair(keyHandle);
                return keyHandle;
            }
            finally
            {
                if (rented is not null)
                {
                    CryptoPool.Return(rented, blobSize);
                }
            }

            static CryptographicException Fail()
            {
                Debug.Fail("Unknown blob type.");
                return new CryptographicException();
            }
        }

        private void ExportKey(uint kind, Span<byte> destination)
        {
            string blobKind = kind switch
            {
                BCRYPT_MLKEM_PRIVATE_SEED_MAGIC => BCRYPT_MLKEM_PRIVATE_SEED_BLOB,
                BCRYPT_MLKEM_PRIVATE_MAGIC => BCRYPT_MLKEM_PRIVATE_BLOB,
                BCRYPT_MLKEM_PUBLIC_MAGIC => BCRYPT_MLKEM_PUBLIC_BLOB,
                _ => throw Fail(),
            };

            ArraySegment<byte> exported = Interop.BCrypt.BCryptExportKey(_key, blobKind);

            try
            {
                Span<byte> exportedSpan = exported;

                unsafe
                {
                    fixed (byte* pExportedSpan = exportedSpan)
                    {
                        BCRYPT_MLKEM_KEY_BLOB* blob = (BCRYPT_MLKEM_KEY_BLOB*)pExportedSpan;

                        if (blob->dwMagic != kind)
                        {
                            Debug.Fail("dwMagic is not expected value");
                            throw new CryptographicException();
                        }

                        int blobHeaderSize = Marshal.SizeOf<BCRYPT_MLKEM_KEY_BLOB>();
                        int keySize = checked((int)blob->cbKey);
                        int paramSetSize = checked((int)blob->cbParameterSet);
                        string paramSet = Marshal.PtrToStringUni((nint)(pExportedSpan + blobHeaderSize))!;
                        string expectedParamSet = GetParameterSet(Algorithm);

                        if (paramSet != expectedParamSet)
                        {
                            throw new CryptographicException(SR.Cryptography_NotValidPublicOrPrivateKey);
                        }

                        exportedSpan.Slice(blobHeaderSize + paramSetSize, keySize).CopyTo(destination);
                    }
                }
            }
            finally
            {
                CryptoPool.Return(exported);
            }

            static CryptographicException Fail()
            {
                Debug.Fail("Unknown blob type.");
                return new CryptographicException();
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BCRYPT_MLKEM_KEY_BLOB
        {
            internal uint dwMagic;
            internal uint cbParameterSet;
            internal uint cbKey;
        }
    }
}
