// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Formats.Asn1;
using System.Security.Cryptography.Asn1;

namespace System.Security.Cryptography
{
    /// <summary>
    ///   Represents an X25519 Diffie-Hellman key.
    /// </summary>
    /// <remarks>
    ///   <para>
    ///     Developers are encouraged to program against the <c>X25519DiffieHellman</c> base class,
    ///     rather than any specific derived class.
    ///     The derived classes are intended for interop with the underlying system
    ///     cryptographic libraries.
    ///   </para>
    /// </remarks>
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
        ///   Derives a raw secret agreement with the other party's key.
        /// </summary>
        /// <param name="otherParty">
        ///   The other party's key.
        /// </param>
        /// <returns>
        ///   The secret agreement.
        /// </returns>
        /// <remarks>
        ///   The raw secret agreement value is expected to be used as input into a Key Derivation Function,
        ///   and not used directly as key material.
        /// </remarks>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="otherParty" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred during the secret agreement derivation.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public byte[] DeriveRawSecretAgreement(X25519DiffieHellman otherParty)
        {
            ArgumentNullException.ThrowIfNull(otherParty);
            ThrowIfDisposed();

            byte[] buffer = new byte[SecretAgreementSizeInBytes];
            DeriveRawSecretAgreementCore(otherParty, buffer);
            return buffer;
        }

        /// <summary>
        ///   Derives a raw secret agreement with the other party's key, writing it into the provided buffer.
        /// </summary>
        /// <param name="otherParty">
        ///   The other party's key.
        /// </param>
        /// <param name="destination">
        ///   The buffer to receive the secret agreement.
        /// </param>
        /// <remarks>
        ///   The raw secret agreement value is expected to be used as input into a Key Derivation Function,
        ///   and not used directly as key material.
        /// </remarks>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="otherParty" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="destination" /> is the incorrect length to receive the secret agreement.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred during the secret agreement derivation.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public void DeriveRawSecretAgreement(X25519DiffieHellman otherParty, Span<byte> destination)
        {
            ArgumentNullException.ThrowIfNull(otherParty);

            if (destination.Length != SecretAgreementSizeInBytes)
            {
                throw new ArgumentException(
                    SR.Format(SR.Argument_DestinationImprecise, SecretAgreementSizeInBytes),
                    nameof(destination));
            }

            DeriveRawSecretAgreementCore(otherParty, destination);
        }

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
        ///   Attempts to export the public-key portion of the current key in the X.509 SubjectPublicKeyInfo format
        ///   into the provided buffer.
        /// </summary>
        /// <param name="destination">
        ///   The buffer to receive the X.509 SubjectPublicKeyInfo value.
        /// </param>
        /// <param name="bytesWritten">
        ///   When this method returns, contains the number of bytes written to the <paramref name="destination"/> buffer.
        ///   This parameter is treated as uninitialized.
        /// </param>
        /// <returns>
        ///   <see langword="true" /> if <paramref name="destination"/> was large enough to hold the result;
        ///   otherwise, <see langword="false" />.
        /// </returns>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred while exporting the key.
        /// </exception>
        public bool TryExportSubjectPublicKeyInfo(Span<byte> destination, out int bytesWritten)
        {
            ThrowIfDisposed();
            return ExportSubjectPublicKeyInfoCore().TryEncode(destination, out bytesWritten);
        }

        /// <summary>
        ///   Exports the public-key portion of the current key in the X.509 SubjectPublicKeyInfo format.
        /// </summary>
        /// <returns>
        ///   A byte array containing the X.509 SubjectPublicKeyInfo representation of the public-key portion of this key.
        /// </returns>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred while exporting the key.
        /// </exception>
        public byte[] ExportSubjectPublicKeyInfo()
        {
            ThrowIfDisposed();
            return ExportSubjectPublicKeyInfoCore().Encode();
        }

        /// <summary>
        ///   When overridden in a derived class, derives a raw secret agreement with the other party's key,
        ///   writing it into the provided buffer.
        /// </summary>
        /// <param name="otherParty">
        ///   The other party's key.
        /// </param>
        /// <param name="destination">
        ///   The buffer to receive the secret agreement.
        /// </param>
        /// <exception cref="CryptographicException">
        ///   An error occurred during the secret agreement derivation.
        /// </exception>
        protected abstract void DeriveRawSecretAgreementCore(X25519DiffieHellman otherParty, Span<byte> destination);

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
        ///   Imports an X25519 Diffie-Hellman key from a private key.
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
        ///   The platform does not support X25519 Diffie-Hellman. Callers can use the <see cref="IsSupported" /> property
        ///   to determine if the platform supports X25519 Diffie-Hellman.
        /// </exception>
        public static X25519DiffieHellman ImportPrivateKey(byte[] source)
        {
            ArgumentNullException.ThrowIfNull(source);
            return ImportPrivateKey(new ReadOnlySpan<byte>(source));
        }

        /// <summary>
        ///   Imports an X25519 Diffie-Hellman key from a private key.
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
        ///   The platform does not support X25519 Diffie-Hellman. Callers can use the <see cref="IsSupported" /> property
        ///   to determine if the platform supports X25519 Diffie-Hellman.
        /// </exception>
        public static X25519DiffieHellman ImportPrivateKey(ReadOnlySpan<byte> source)
        {
            if (source.Length != PrivateKeySizeInBytes)
                throw new ArgumentException(SR.Argument_PrivateKeyWrongSizeForAlgorithm, nameof(source));

            ThrowIfNotSupported();
            return X25519DiffieHellmanImplementation.ImportPrivateKeyImpl(source);
        }

        /// <summary>
        ///   Imports an X25519 Diffie-Hellman key from a public key.
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
        ///   The platform does not support X25519 Diffie-Hellman. Callers can use the <see cref="IsSupported" /> property
        ///   to determine if the platform supports X25519 Diffie-Hellman.
        /// </exception>
        public static X25519DiffieHellman ImportPublicKey(byte[] source)
        {
            ArgumentNullException.ThrowIfNull(source);
            return ImportPublicKey(new ReadOnlySpan<byte>(source));
        }

        /// <summary>
        ///   Imports an X25519 Diffie-Hellman key from a public key.
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
        ///   The platform does not support X25519 Diffie-Hellman. Callers can use the <see cref="IsSupported" /> property
        ///   to determine if the platform supports X25519 Diffie-Hellman.
        /// </exception>
        public static X25519DiffieHellman ImportPublicKey(ReadOnlySpan<byte> source)
        {
            if (source.Length != PublicKeySizeInBytes)
                throw new ArgumentException(SR.Argument_PublicKeyWrongSizeForAlgorithm, nameof(source));

            ThrowIfNotSupported();
            return X25519DiffieHellmanImplementation.ImportPublicKeyImpl(source);
        }

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

        private AsnWriter ExportSubjectPublicKeyInfoCore()
        {
            Span<byte> publicKey = stackalloc byte[PublicKeySizeInBytes];
            ExportPublicKeyCore(publicKey);

            ValueSubjectPublicKeyInfoAsn spki = new ValueSubjectPublicKeyInfoAsn
            {
                Algorithm = new ValueAlgorithmIdentifierAsn
                {
                    Algorithm = Oids.X25519,
                },
                SubjectPublicKey = publicKey,
            };

            // The ASN.1 overhead of a SubjectPublicKeyInfo encoding a public key is 12 bytes.
            // Round it off to 16.
            const int Capacity = 16 + PublicKeySizeInBytes;
            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER, Capacity);
            spki.Encode(writer);
            return writer;
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
