// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;

namespace System.Security.Cryptography
{
    public abstract class EdDsa : AsymmetricAlgorithm
    {
        public abstract int GetSignatureSize();
        public abstract void GenerateKey();

        public abstract byte[] ExportPrivateKey();
        public abstract byte[] ExportPublicKey();

        public abstract void ImportPrivateKey(ReadOnlySpan<byte> privateKey);
        public abstract void ImportPublicKey(ReadOnlySpan<byte> publicKey);

        protected abstract bool TrySignDataCore(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten);
        protected abstract bool VerifyDataCore(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);

        public bool TrySignData(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten)
        {
            if (destination.Length < GetSignatureSize())
            {
                bytesWritten = 0;
                return false;
            }

            return TrySignDataCore(data, destination, out bytesWritten);
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
            byte[] signature = new byte[GetSignatureSize()];
            int written = SignData(data, signature);
            Debug.Assert(written == GetSignatureSize());
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

            if (signature.Length != GetSignatureSize())
            {
                return false;
            }

            return VerifyDataCore(new ReadOnlySpan<byte>(data), new ReadOnlySpan<byte>(signature));
        }

        public bool VerifyData(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        {
            if (signature.Length != GetSignatureSize())
            {
                return false;
            }

            return VerifyDataCore(data, signature);
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
    }
}
