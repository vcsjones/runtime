// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;

namespace System.Security.Cryptography
{
    public abstract class X25519DiffieHellman : IDisposable
    {
        private bool _disposed;

        /// <summary>
        ///   The size of the secret agreement, in bytes.
        /// </summary>
        public const int SecretAgreementSizeInBytes = 32;

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
        public static bool IsSupported => X25519DiffieHellmanImplementation.IsSupported;

        /// <summary>
        ///   Generates a new X25519 Diffie-Hellman key.
        /// </summary>
        /// <returns>
        ///   The generated key.
        /// </returns>
        /// <exception cref="CryptographicException">
        ///   An error occurred generating the X25519 Diffie-Hellman key.
        /// </exception>
        /// <exception cref="PlatformNotSupportedException">
        ///   The platform does not support X25519 Diffie-Hellman. Callers can use the <see cref="IsSupported" /> property
        ///   to determine if the platform supports X25519 Diffie-Hellman.
        /// </exception>
        public static X25519DiffieHellman GenerateKey()
        {
            ThrowIfNotSupported();
            return X25519DiffieHellmanImplementation.GenerateKeyImpl();
        }

        public byte[] ExportPublicKey()
        {
            ThrowIfDisposed();

            byte[] buffer = new byte[PublicKeySizeInBytes];
            ExportPublicKeyCore(buffer);
            return buffer;
        }

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

        protected abstract void ExportPublicKeyCore(Span<byte> destination);

        /// <summary>
        ///   Releases all resources used by the <see cref="X25519DiffieHellman"/> class.
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
        ///   resources used by the current instance of the <see cref="X25519DiffieHellman"/> class.
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
            ObjectDisposedException.ThrowIf(_disposed, typeof(X25519DiffieHellman));
        }

        private protected static void ThrowIfNotSupported()
        {
            if (!IsSupported)
            {
                throw new PlatformNotSupportedException(
                    SR.Format(SR.Cryptography_AlgorithmNotSupported,
                    nameof(X25519DiffieHellman)));
            }
        }
    }
}
