// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;

namespace System.Security.Cryptography
{
    internal sealed class IncrementalHash : IDisposable
    {
        private HashAlgorithm _hash;

        private IncrementalHash(HashAlgorithm hash)
        {
            _hash = hash;
        }

        public static IncrementalHash CreateHash(HashAlgorithmName hashAlgorithm)
        {
            HashAlgorithm hash = hashAlgorithm.Name switch
            {
#pragma warning disable CA5351
                nameof(HashAlgorithmName.MD5) => MD5.Create(),
#pragma warning restore CA5351
#pragma warning disable CA5350
                nameof(HashAlgorithmName.SHA1) => SHA1.Create(),
#pragma warning restore CA5350
                nameof(HashAlgorithmName.SHA256) => SHA256.Create(),
                nameof(HashAlgorithmName.SHA384) => SHA384.Create(),
                nameof(HashAlgorithmName.SHA512) => SHA512.Create(),
                _ => throw new CryptographicException(SR.Cryptography_UnknownHashAlgorithm, hashAlgorithm.Name),
            };

            return new IncrementalHash(hash);
        }

        public static IncrementalHash CreateHMAC(HashAlgorithmName hashAlgorithm, byte[] macKey)
        {
            HMAC hmac = hashAlgorithm.Name switch
            {
#pragma warning disable CA5351
                nameof(HashAlgorithmName.MD5) => new HMACMD5(macKey),
#pragma warning restore CA5351
#pragma warning disable CA5350
                nameof(HashAlgorithmName.SHA1) => new HMACSHA1(macKey),
#pragma warning restore CA5350
                nameof(HashAlgorithmName.SHA256) => new HMACSHA256(macKey),
                nameof(HashAlgorithmName.SHA384) => new HMACSHA384(macKey),
                nameof(HashAlgorithmName.SHA512) => new HMACSHA512(macKey),
                _ => throw new CryptographicException(SR.Cryptography_UnknownHashAlgorithm, hashAlgorithm.Name),
            };

            return new IncrementalHash(hmac);
        }

        public void Dispose()
        {
            _hash.Dispose();
        }

        public void AppendData(byte[] data)
        {
            _hash.TransformBlock(data, 0, data.Length, null, 0);
        }

        public void AppendData(byte[] data, int offset, int count)
        {
            _hash.TransformBlock(data, offset, count, null, 0);
        }

        internal bool TryGetHashAndReset(
            Span<byte> destination,
            out int bytesWritten)
        {
            if (destination.Length < _hash.HashSize / 8)
            {
                bytesWritten = 0;
                return false;
            }

            _hash.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            byte[] actual = _hash.Hash;
            _hash.Initialize();

            Debug.Assert(actual.Length * 8 == _hash.HashSize);
            actual.AsSpan().CopyTo(destination);
            bytesWritten = actual.Length;
            return true;
        }
    }
}
