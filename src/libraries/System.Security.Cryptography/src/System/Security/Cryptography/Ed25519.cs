// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Versioning;

namespace System.Security.Cryptography
{
    public abstract partial class Ed25519 : AsymmetricAlgorithm
    {
        private protected const int PublicKeySize = 32;
        private protected const int PrivateKeySize = 32;
        private static readonly KeySizes[] s_legalKeySizes = new[] { new KeySizes(minSize: 256, maxSize: 256, skipSize: 0) };

        public int SignatureSizeInBytes => 64;

        [UnsupportedOSPlatform("android")]
        [UnsupportedOSPlatform("browser")]
        [UnsupportedOSPlatform("windows")]
        [UnsupportedOSPlatform("ios")]
        [UnsupportedOSPlatform("tvos")]
        [UnsupportedOSPlatform("maccatalyst")]
        public static new partial Ed25519 Create();

        protected Ed25519()
        {
            KeySizeValue = PublicKeySize * 8;
            LegalKeySizesValue = s_legalKeySizes;
        }

        public override string SignatureAlgorithm => "Ed25519";
        public override string? KeyExchangeAlgorithm => null;

        public abstract void GenerateKey();

        protected abstract int ExportPrivateKeyCore(Span<byte> destination);
        protected abstract int ExportPublicKeyCore(Span<byte> destination);

        protected abstract void ImportPrivateKeyCore(ReadOnlySpan<byte> privateKey);
        protected abstract void ImportPublicKeyCore(ReadOnlySpan<byte> publicKey);

        protected abstract int SignDataCore(ReadOnlySpan<byte> data, Span<byte> destination);
        protected abstract bool VerifyDataCore(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);

        public bool TrySignData(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten)
        {
            if (destination.Length < SignatureSizeInBytes)
            {
                bytesWritten = 0;
                return false;
            }

            bytesWritten = SignDataCore(data, destination);
            return true;
        }

        public int SignData(ReadOnlySpan<byte> data, Span<byte> destination)
        {
            if (TrySignData(data, destination, out int bytesWritten))
            {
                return bytesWritten;
            }

            throw new ArgumentException(SR.Argument_DestinationTooShort, nameof(destination));
        }

        public byte[] SignData(ReadOnlySpan<byte> data)
        {
            byte[] signature = new byte[SignatureSizeInBytes];
            int written = SignData(data, signature);
            Debug.Assert(written == SignatureSizeInBytes);
            return signature;
        }

        public byte[] SignData(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);

            return SignData(new ReadOnlySpan<byte>(data));
        }

        public bool VerifyData(byte[] data, byte[] signature)
        {
            ArgumentNullException.ThrowIfNull(data);
            ArgumentNullException.ThrowIfNull(signature);

            if (signature.Length != SignatureSizeInBytes)
            {
                return false;
            }

            return VerifyDataCore(new ReadOnlySpan<byte>(data), new ReadOnlySpan<byte>(signature));
        }

        public bool VerifyData(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        {
            if (signature.Length != SignatureSizeInBytes)
            {
                return false;
            }

            return VerifyDataCore(data, signature);
        }

        public void ImportPrivateKey(ReadOnlySpan<byte> privateKey)
        {
            if (privateKey.Length != PrivateKeySize)
            {
                throw new CryptographicException(SR.Cryptography_NotValidPrivateKey);
            }

            ImportPrivateKeyCore(privateKey);
        }

        public void ImportPublicKey(ReadOnlySpan<byte> publicKey)
        {
            if (publicKey.Length != PublicKeySize)
            {
                throw new CryptographicException(SR.Cryptography_NotValidPublicKey);
            }

            ImportPublicKeyCore(publicKey);
        }

        public void ImportPrivateKey(byte[] privateKey)
        {
            ArgumentNullException.ThrowIfNull(privateKey);
            ImportPrivateKey(new ReadOnlySpan<byte>(privateKey));
        }

        public void ImportPublicKey(byte[] publicKey)
        {
            ArgumentNullException.ThrowIfNull(publicKey);
            ImportPublicKey(new ReadOnlySpan<byte>(publicKey));
        }

        public byte[] ExportPrivateKey()
        {
            byte[] privateKey = GC.AllocateArray<byte>(PrivateKeySize, pinned: true);
            int written = ExportPrivateKeyCore(privateKey);

            if (written != PrivateKeySize)
            {
                CryptographicOperations.ZeroMemory(privateKey);
                throw new CryptographicException();
            }

            return privateKey;
        }

        public byte[] ExportPublicKey()
        {
            byte[] publicKey = new byte[PublicKeySize];
            int written = ExportPublicKeyCore(publicKey);

            if (written != PublicKeySize)
            {
                throw new CryptographicException();
            }

            return publicKey;
        }

        public int ExportPublicKey(Span<byte> destination)
        {
            if (destination.Length < PublicKeySize)
                throw new ArgumentException(SR.Argument_DestinationTooShort, nameof(destination));

            return ExportPublicKeyCore(destination);
        }

        public int ExportPrivateKey(Span<byte> destination)
        {
            if (destination.Length < PrivateKeySize)
                throw new ArgumentException(SR.Argument_DestinationTooShort, nameof(destination));

            return ExportPrivateKeyCore(destination);
        }

        public bool TryExportPublicKey(Span<byte> destination, out int bytesWritten)
        {
            if (destination.Length < PublicKeySize)
            {
                bytesWritten = 0;
                return false;
            }

            int written = ExportPublicKeyCore(destination);

            if (written != PublicKeySize)
            {
                throw new CryptographicException();
            }

            bytesWritten = written;
            return true;
        }

        public bool TryExportPrivateKey(Span<byte> destination, out int bytesWritten)
        {
            if (destination.Length < PrivateKeySize)
            {
                bytesWritten = 0;
                return false;
            }

            int written = ExportPrivateKeyCore(destination);

            if (written != PrivateKeySize)
            {
                throw new CryptographicException();
            }

            bytesWritten = written;
            return true;
        }
    }
}
