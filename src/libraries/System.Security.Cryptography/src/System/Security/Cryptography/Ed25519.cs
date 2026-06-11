// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Security.Cryptography
{
    /// <summary>
    ///   Represents an Ed25519 key.
    /// </summary>
    /// <remarks>
    ///   <para>
    ///     Developers are encouraged to program against the <c>Ed25519</c> base class,
    ///     rather than any specific derived class.
    ///     The derived classes are intended for interop with the underlying system
    ///     cryptographic libraries.
    ///   </para>
    /// </remarks>
    public abstract class Ed25519 : IDisposable
    {
        private bool _disposed;

        /// <summary>
        ///   The size of an Ed25519 signature, in bytes.
        /// </summary>
        public const int SignatureSizeInBytes = 64;

        /// <summary>
        ///   The size of the private key, in bytes.
        /// </summary>
        public const int PrivateKeySizeInBytes = 32;

        /// <summary>
        ///   The size of the public key, in bytes.
        /// </summary>
        public const int PublicKeySizeInBytes = 32;

        /// <summary>
        ///   Gets a value that indicates whether the algorithm is supported on the current platform.
        /// </summary>
        /// <value>
        ///   <see langword="true" /> if the algorithm is supported; otherwise, <see langword="false" />.
        /// </value>
        public static bool IsSupported => Ed25519Implementation.IsSupported;

        /// <summary>
        ///   Initializes a new instance of the <see cref="Ed25519"/> class.
        /// </summary>
        protected Ed25519()
        {
        }

        /// <summary>
        ///   Generates a new Ed25519 key.
        /// </summary>
        /// <returns>
        ///   The generated key.
        /// </returns>
        /// <exception cref="CryptographicException">
        ///   An error occurred generating the Ed25519 key.
        /// </exception>
        /// <exception cref="PlatformNotSupportedException">
        ///   The platform does not support Ed25519. Callers can use the <see cref="IsSupported" /> property
        ///   to determine if the platform supports Ed25519.
        /// </exception>
        public static Ed25519 GenerateKey()
        {
            ThrowIfNotSupported();
            return Ed25519Implementation.GenerateKeyImpl();
        }

        /// <summary>
        ///   Imports an Ed25519 key from a private key.
        /// </summary>
        /// <param name="source">
        ///   The private key.
        /// </param>
        /// <returns>
        ///   The imported key.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="source" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="source" /> has a length that is not <see cref="PrivateKeySizeInBytes" />.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred while importing the key.
        /// </exception>
        /// <exception cref="PlatformNotSupportedException">
        ///   The platform does not support Ed25519. Callers can use the <see cref="IsSupported" /> property
        ///   to determine if the platform supports Ed25519.
        /// </exception>
        public static Ed25519 ImportPrivateKey(byte[] source)
        {
            ArgumentNullException.ThrowIfNull(source);
            return ImportPrivateKey(new ReadOnlySpan<byte>(source));
        }

        /// <summary>
        ///   Imports an Ed25519 key from a private key.
        /// </summary>
        /// <param name="source">
        ///   The private key.
        /// </param>
        /// <returns>
        ///   The imported key.
        /// </returns>
        /// <exception cref="ArgumentException">
        ///   <paramref name="source" /> has a length that is not <see cref="PrivateKeySizeInBytes" />.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred while importing the key.
        /// </exception>
        /// <exception cref="PlatformNotSupportedException">
        ///   The platform does not support Ed25519. Callers can use the <see cref="IsSupported" /> property
        ///   to determine if the platform supports Ed25519.
        /// </exception>
        public static Ed25519 ImportPrivateKey(ReadOnlySpan<byte> source)
        {
            if (source.Length != PrivateKeySizeInBytes)
                throw new ArgumentException(SR.Argument_PrivateKeyWrongSizeForAlgorithm, nameof(source));

            ThrowIfNotSupported();
            return Ed25519Implementation.ImportPrivateKeyImpl(source);
        }

        /// <summary>
        ///   Imports an Ed25519 key from a public key.
        /// </summary>
        /// <param name="source">
        ///   The public key.
        /// </param>
        /// <returns>
        ///   The imported key.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="source" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="source" /> has a length that is not <see cref="PublicKeySizeInBytes" />.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred while importing the key.
        /// </exception>
        /// <exception cref="PlatformNotSupportedException">
        ///   The platform does not support Ed25519. Callers can use the <see cref="IsSupported" /> property
        ///   to determine if the platform supports Ed25519.
        /// </exception>
        public static Ed25519 ImportPublicKey(byte[] source)
        {
            ArgumentNullException.ThrowIfNull(source);
            return ImportPublicKey(new ReadOnlySpan<byte>(source));
        }

        /// <summary>
        ///   Imports an Ed25519 key from a public key.
        /// </summary>
        /// <param name="source">
        ///   The public key.
        /// </param>
        /// <returns>
        ///   The imported key.
        /// </returns>
        /// <exception cref="ArgumentException">
        ///   <paramref name="source" /> has a length that is not <see cref="PublicKeySizeInBytes" />.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred while importing the key.
        /// </exception>
        /// <exception cref="PlatformNotSupportedException">
        ///   The platform does not support Ed25519. Callers can use the <see cref="IsSupported" /> property
        ///   to determine if the platform supports Ed25519.
        /// </exception>
        public static Ed25519 ImportPublicKey(ReadOnlySpan<byte> source)
        {
            if (source.Length != PublicKeySizeInBytes)
                throw new ArgumentException(SR.Argument_PublicKeyWrongSizeForAlgorithm, nameof(source));

            ThrowIfNotSupported();
            return Ed25519Implementation.ImportPublicKeyImpl(source);
        }

        /// <summary>
        ///   Exports the private key.
        /// </summary>
        /// <returns>
        ///   The private key.
        /// </returns>
        /// <exception cref="CryptographicException">
        ///   An error occurred while exporting the key.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public byte[] ExportPrivateKey()
        {
            ThrowIfDisposed();

            byte[] buffer = new byte[PrivateKeySizeInBytes];
            ExportPrivateKeyCore(buffer);
            return buffer;
        }

        /// <summary>
        ///   Exports the private key into the provided buffer.
        /// </summary>
        /// <param name="destination">
        ///   The buffer to receive the private key.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <paramref name="destination" /> is the incorrect length to receive the private key.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred while exporting the key.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public void ExportPrivateKey(Span<byte> destination)
        {
            if (destination.Length != PrivateKeySizeInBytes)
            {
                throw new ArgumentException(
                    SR.Format(SR.Argument_DestinationImprecise, PrivateKeySizeInBytes),
                    nameof(destination));
            }

            ThrowIfDisposed();
            ExportPrivateKeyCore(destination);
        }

        /// <summary>
        ///   Exports the public key.
        /// </summary>
        /// <returns>
        ///   The public key.
        /// </returns>
        /// <exception cref="CryptographicException">
        ///   An error occurred while exporting the key.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public byte[] ExportPublicKey()
        {
            ThrowIfDisposed();

            byte[] buffer = new byte[PublicKeySizeInBytes];
            ExportPublicKeyCore(buffer);
            return buffer;
        }

        /// <summary>
        ///   Exports the public key into the provided buffer.
        /// </summary>
        /// <param name="destination">
        ///   The buffer to receive the public key.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <paramref name="destination" /> is the incorrect length to receive the public key.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred while exporting the key.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public void ExportPublicKey(Span<byte> destination)
        {
            if (destination.Length != PublicKeySizeInBytes)
            {
                throw new ArgumentException(
                    SR.Format(SR.Argument_DestinationImprecise, PublicKeySizeInBytes),
                    nameof(destination));
            }

            ThrowIfDisposed();
            ExportPublicKeyCore(destination);
        }

        /// <summary>
        ///   When overridden in a derived class, exports the private key into the provided buffer.
        /// </summary>
        /// <param name="destination">
        ///   The buffer to receive the private key.
        /// </param>
        protected abstract void ExportPrivateKeyCore(Span<byte> destination);

        /// <summary>
        ///   When overridden in a derived class, exports the public key into the provided buffer.
        /// </summary>
        /// <param name="destination">
        ///   The buffer to receive the public key.
        /// </param>
        protected abstract void ExportPublicKeyCore(Span<byte> destination);

        /// <summary>
        ///   Signs the specified data.
        /// </summary>
        /// <param name="data">
        ///   The data to sign.
        /// </param>
        /// <returns>
        ///   The signature.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="data"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        /// <exception cref="CryptographicException">
        ///   <para>The instance represents only a public key.</para>
        ///   <para>-or-</para>
        ///   <para>An error occurred while signing the data.</para>
        /// </exception>
        public byte[] SignData(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);

            byte[] destination = new byte[SignatureSizeInBytes];
            SignData(new ReadOnlySpan<byte>(data), destination);
            return destination;
        }

        /// <summary>
        ///   Signs the specified data, writing the signature into the provided buffer.
        /// </summary>
        /// <param name="data">
        ///   The data to sign.
        /// </param>
        /// <param name="destination">
        ///   The buffer to receive the signature. Its length must be exactly <see cref="SignatureSizeInBytes"/>.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   The buffer in <paramref name="destination"/> is the incorrect length to receive the signature.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        /// <exception cref="CryptographicException">
        ///   <para>The instance represents only a public key.</para>
        ///   <para>-or-</para>
        ///   <para>An error occurred while signing the data.</para>
        /// </exception>
        public void SignData(ReadOnlySpan<byte> data, Span<byte> destination)
        {
            if (destination.Length != SignatureSizeInBytes)
            {
                throw new ArgumentException(
                    SR.Format(SR.Argument_DestinationImprecise, SignatureSizeInBytes),
                    nameof(destination));
            }

            ThrowIfDisposed();
            SignDataCore(data, destination);
        }

        /// <summary>
        ///   When overridden in a derived class, signs the specified data, writing the signature into the provided buffer.
        /// </summary>
        /// <param name="data">
        ///   The data to sign.
        /// </param>
        /// <param name="destination">
        ///   The buffer to receive the signature.
        /// </param>
        protected abstract void SignDataCore(ReadOnlySpan<byte> data, Span<byte> destination);

        /// <summary>
        ///   Verifies that the specified signature is valid for this key and the provided data.
        /// </summary>
        /// <param name="data">
        ///   The data to verify.
        /// </param>
        /// <param name="signature">
        ///   The signature to verify.
        /// </param>
        /// <returns>
        ///   <see langword="true"/> if the signature validates the data; otherwise, <see langword="false"/>.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="data"/> or <paramref name="signature"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred while verifying the data.
        /// </exception>
        public bool VerifyData(byte[] data, byte[] signature)
        {
            ArgumentNullException.ThrowIfNull(data);
            ArgumentNullException.ThrowIfNull(signature);

            return VerifyData(new ReadOnlySpan<byte>(data), new ReadOnlySpan<byte>(signature));
        }

        /// <summary>
        ///   Verifies that the specified signature is valid for this key and the provided data.
        /// </summary>
        /// <param name="data">
        ///   The data to verify.
        /// </param>
        /// <param name="signature">
        ///   The signature to verify.
        /// </param>
        /// <returns>
        ///   <see langword="true"/> if the signature validates the data; otherwise, <see langword="false"/>.
        /// </returns>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred while verifying the data.
        /// </exception>
        public bool VerifyData(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        {
            ThrowIfDisposed();

            if (signature.Length != SignatureSizeInBytes)
            {
                return false;
            }

            return VerifyDataCore(data, signature);
        }

        /// <summary>
        ///   When overridden in a derived class, verifies that the specified signature is valid for this key and the provided data.
        /// </summary>
        /// <param name="data">
        ///   The data to verify.
        /// </param>
        /// <param name="signature">
        ///   The signature to verify.
        /// </param>
        /// <returns>
        ///   <see langword="true"/> if the signature validates the data; otherwise, <see langword="false"/>.
        /// </returns>
        protected abstract bool VerifyDataCore(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);

        /// <summary>
        ///   Releases all resources used by the <see cref="Ed25519"/> class.
        /// </summary>
        public void Dispose()
        {
            if (!_disposed)
            {
                _disposed = true;
                Dispose(true);
                GC.SuppressFinalize(this);
            }
        }

        /// <summary>
        ///   Called by the <c>Dispose()</c> and <c>Finalize()</c> methods to release the managed and unmanaged
        ///   resources used by the current instance of the <see cref="Ed25519"/> class.
        /// </summary>
        /// <param name="disposing">
        ///   <see langword="true" /> to release managed and unmanaged resources;
        ///   <see langword="false" /> to release only unmanaged resources.
        /// </param>
        protected virtual void Dispose(bool disposing)
        {
        }

        private protected void ThrowIfDisposed()
        {
            ObjectDisposedException.ThrowIf(_disposed, typeof(Ed25519));
        }

        private protected static void ThrowIfNotSupported()
        {
            if (!IsSupported)
            {
                throw new PlatformNotSupportedException(
                    SR.Format(SR.Cryptography_AlgorithmNotSupported, nameof(Ed25519)));
            }
        }
    }
}
