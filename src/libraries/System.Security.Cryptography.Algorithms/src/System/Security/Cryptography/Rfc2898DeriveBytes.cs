// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Buffers.Binary;
using System.Text;
using System.Diagnostics;

using Internal.Cryptography;

namespace System.Security.Cryptography
{
    public class Rfc2898DeriveBytes : DeriveBytes
    {
        private const int MinimumSaltSize = 8;

        private readonly byte[] _password;
        private byte[] _salt;
        private uint _iterations;
        private IncrementalHash _hmac;
        private readonly int _blockSize;

        private byte[] _buffer = null!; // Initialized in helper
        private uint _block;
        private int _startIndex;
        private int _endIndex;

        public HashAlgorithmName HashAlgorithm { get; }

        public Rfc2898DeriveBytes(byte[] password, byte[] salt, int iterations)
            : this(password, salt, iterations, HashAlgorithmName.SHA1)
        {
        }

        public Rfc2898DeriveBytes(byte[] password, byte[] salt, int iterations, HashAlgorithmName hashAlgorithm)
        {
            if (salt == null)
                throw new ArgumentNullException(nameof(salt));
            if (salt.Length < MinimumSaltSize)
                throw new ArgumentException(SR.Cryptography_PasswordDerivedBytes_FewBytesSalt, nameof(salt));
            if (iterations <= 0)
                throw new ArgumentOutOfRangeException(nameof(iterations), SR.ArgumentOutOfRange_NeedPosNum);
            if (password == null)
                throw new NullReferenceException();  // This "should" be ArgumentNullException but for compat, we throw NullReferenceException.

            _salt = salt.CloneByteArray();
            _iterations = (uint)iterations;
            _password = password.CloneByteArray();
            HashAlgorithm = hashAlgorithm;
            (_hmac, _blockSize) = OpenHmac();

            Initialize();
        }

        public Rfc2898DeriveBytes(string password, byte[] salt)
             : this(password, salt, 1000)
        {
        }

        public Rfc2898DeriveBytes(string password, byte[] salt, int iterations)
            : this(password, salt, iterations, HashAlgorithmName.SHA1)
        {
        }

        public Rfc2898DeriveBytes(string password, byte[] salt, int iterations, HashAlgorithmName hashAlgorithm)
            : this(Encoding.UTF8.GetBytes(password), salt, iterations, hashAlgorithm)
        {
        }

        public Rfc2898DeriveBytes(string password, int saltSize)
            : this(password, saltSize, 1000)
        {
        }

        public Rfc2898DeriveBytes(string password, int saltSize, int iterations)
            : this(password, saltSize, iterations, HashAlgorithmName.SHA1)
        {
        }

        public Rfc2898DeriveBytes(string password, int saltSize, int iterations, HashAlgorithmName hashAlgorithm)
        {
            if (saltSize < 0)
                throw new ArgumentOutOfRangeException(nameof(saltSize), SR.ArgumentOutOfRange_NeedNonNegNum);
            if (saltSize < MinimumSaltSize)
                throw new ArgumentException(SR.Cryptography_PasswordDerivedBytes_FewBytesSalt, nameof(saltSize));
            if (iterations <= 0)
                throw new ArgumentOutOfRangeException(nameof(iterations), SR.ArgumentOutOfRange_NeedPosNum);

            _salt = new byte[saltSize];
            RandomNumberGenerator.Fill(_salt);

            _iterations = (uint)iterations;
            _password = Encoding.UTF8.GetBytes(password);
            HashAlgorithm = hashAlgorithm;
            (_hmac, _blockSize) = OpenHmac();

            Initialize();
        }

        public int IterationCount
        {
            get
            {
                return (int)_iterations;
            }

            set
            {
                if (value <= 0)
                    throw new ArgumentOutOfRangeException(nameof(value), SR.ArgumentOutOfRange_NeedPosNum);
                _iterations = (uint)value;
                Initialize();
            }
        }

        public byte[] Salt
        {
            get => _salt.CloneByteArray();

            set
            {
                if (value == null)
                    throw new ArgumentNullException(nameof(value));
                if (value.Length < MinimumSaltSize)
                    throw new ArgumentException(SR.Cryptography_PasswordDerivedBytes_FewBytesSalt);

                _salt = value.CloneByteArray();
                Initialize();
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_hmac != null)
                {
                    _hmac.Dispose();
                    _hmac = null!;
                }

                if (_buffer != null)
                    Array.Clear(_buffer, 0, _buffer.Length);
                if (_password != null)
                    Array.Clear(_password, 0, _password.Length);
                if (_salt != null)
                    Array.Clear(_salt, 0, _salt.Length);
            }
            base.Dispose(disposing);
        }

        public override byte[] GetBytes(int cb)
        {
            Debug.Assert(_blockSize > 0);

            if (cb <= 0)
                throw new ArgumentOutOfRangeException(nameof(cb), SR.ArgumentOutOfRange_NeedPosNum);
            byte[] password = new byte[cb];

            int offset = 0;

            // Drain the existing buffered content first, if any.
            int size = _endIndex - _startIndex;
            if (size > 0)
            {
                if (cb >= size)
                {
                    Buffer.BlockCopy(_buffer, _startIndex, password, 0, size);
                    _startIndex = _endIndex = 0;
                    offset += size;
                }
                else
                {
                    // The buffered contents had enough to fill the requested
                    // amount of data, copy and return.
                    Buffer.BlockCopy(_buffer, _startIndex, password, 0, cb);
                    _startIndex += cb;
                    return password;
                }
            }

            // The buffer should be empty at this point. We should have either
            // returned early if there was enough in the buffer, or drained all
            // of it.
            Debug.Assert(_startIndex == 0 && _endIndex == 0, "Invalid start or end index in the internal buffer.");

            while (offset < cb)
            {
                Prf(password.AsSpan(offset), _buffer, out int bytesWrittenToPassword, out int bytesWrittenToBuffer);
                offset += bytesWrittenToPassword;
                _startIndex = 0;
                _endIndex = bytesWrittenToBuffer;
            }

            return password;
        }

        public byte[] CryptDeriveKey(string algname, string alghashname, int keySize, byte[] rgbIV)
        {
            // If this were to be implemented here, CAPI would need to be used (not CNG) because of
            // unfortunate differences between the two. Using CNG would break compatibility. Since this
            // assembly currently doesn't use CAPI it would require non-trivial additions.
            // In addition, if implemented here, only Windows would be supported as it is intended as
            // a thin wrapper over the corresponding native API.
            // Note that this method is implemented in PasswordDeriveBytes (in the Csp assembly) using CAPI.
            throw new PlatformNotSupportedException();
        }

        public override void Reset()
        {
            Initialize();
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security", "CA5350", Justification = "HMACSHA1 is needed for compat. (https://github.com/dotnet/runtime/issues/17618)")]
        private (IncrementalHash Hmac, int BlockSizeBytes) OpenHmac()
        {
            Debug.Assert(_password != null);

            HashAlgorithmName hashAlgorithm = HashAlgorithm;

            if (string.IsNullOrEmpty(hashAlgorithm.Name))
                throw new CryptographicException(SR.Cryptography_HashAlgorithmNameNullOrEmpty);

            if (hashAlgorithm == HashAlgorithmName.SHA1)
                return (IncrementalHash.CreateHMAC(HashAlgorithmName.SHA1, _password), 160 / 8);
            if (hashAlgorithm == HashAlgorithmName.SHA256)
                return (IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, _password), 256 / 8);
            if (hashAlgorithm == HashAlgorithmName.SHA384)
                return (IncrementalHash.CreateHMAC(HashAlgorithmName.SHA384, _password), 384 / 8);
            if (hashAlgorithm == HashAlgorithmName.SHA512)
                return (IncrementalHash.CreateHMAC(HashAlgorithmName.SHA512, _password), 512 / 8);

            throw new CryptographicException(SR.Format(SR.Cryptography_UnknownHashAlgorithm, hashAlgorithm.Name));
        }

        private void Initialize()
        {
            if (_buffer != null)
                Array.Clear(_buffer, 0, _buffer.Length);
            _buffer = new byte[_blockSize];
            _block = 1;
            _startIndex = _endIndex = 0;
        }

        // This function is defined as follows:
        // Func (S, i) = HMAC(S || i) ^ HMAC2(S || i) ^ ... ^ HMAC(iterations) (S || i)
        // where i is the block number.
        private void Prf(Span<byte> destination, Span<byte> spillBuffer, out int bytesWrittenDestination, out int bytesWrittenSpilled)
        {
            Span<byte> blockSpan = stackalloc byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32BigEndian(blockSpan, _block);

            // We shouldn't spill a whole block but we should have room for it.
            Debug.Assert(spillBuffer.Length >= _blockSize);
            Debug.Assert(destination.Length > 0);
            Debug.Assert(_endIndex == 0);
            Debug.Assert(_startIndex == 0);


            // The biggest _blockSize we have is from SHA512, which is 64 bytes.
            // Since we have a closed set of supported hash algorithms (OpenHmac())
            // we can know this always fits.
            Span<byte> uiSpan = stackalloc byte[64];
            uiSpan = uiSpan.Slice(0, _blockSize);

            // If the destination has enough space to hold a whole block, we can
            // use that. Otherwise we need a temporary place to hold a whole
            // output from the MAC.
            bool willSpill = destination.Length < _blockSize;
            Span<byte> target = willSpill ? stackalloc byte[64] : destination;
            target = target.Slice(0, _blockSize);

            _hmac.AppendData(_salt);
            _hmac.AppendData(blockSpan);

            if (!_hmac.TryGetHashAndReset(uiSpan, out int bytesWritten) || bytesWritten != _blockSize)
            {
                throw new CryptographicException();
            }

            uiSpan.CopyTo(target);

            for (int i = 2; i <= _iterations; i++)
            {
                _hmac.AppendData(uiSpan);

                if (!_hmac.TryGetHashAndReset(uiSpan, out bytesWritten) || bytesWritten != _blockSize)
                {
                    throw new CryptographicException();
                }

                for (int j = 0; j < target.Length; j++)
                {
                    target[j] ^= uiSpan[j];
                }
            }

            // increment the block count.
            _block++;

            if (willSpill)
            {
                ReadOnlySpan<byte> spillover = target.Slice(destination.Length);
                target.Slice(0, destination.Length).CopyTo(destination);
                spillover.CopyTo(spillBuffer);
                bytesWrittenDestination = destination.Length;
                bytesWrittenSpilled = spillover.Length;
            }
            else
            {
                bytesWrittenDestination = _blockSize;
                bytesWrittenSpilled = 0;
            }
        }
    }
}
