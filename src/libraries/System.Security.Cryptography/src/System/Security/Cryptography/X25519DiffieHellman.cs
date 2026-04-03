// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Formats.Asn1;
using System.Security.Cryptography.Asn1;
using Internal.Cryptography;

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
        ///   Exports the public-key portion of the current key in a PEM-encoded representation of
        ///   the X.509 SubjectPublicKeyInfo format.
        /// </summary>
        /// <returns>
        ///   A string containing the PEM-encoded representation of the X.509 SubjectPublicKeyInfo
        ///   representation of the public-key portion of this key.
        /// </returns>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred while exporting the key.
        /// </exception>
        public string ExportSubjectPublicKeyInfoPem()
        {
            ThrowIfDisposed();
            AsnWriter writer = ExportSubjectPublicKeyInfoCore();
            // SPKI does not contain sensitive data.
            return Helpers.EncodeAsnWriterToPem(PemLabels.SpkiPublicKey, writer, clear: false);
        }

        /// <summary>
        ///   Attempts to export the current key in the PKCS#8 PrivateKeyInfo format
        ///   into the provided buffer.
        /// </summary>
        /// <param name="destination">
        ///   The buffer to receive the PKCS#8 PrivateKeyInfo value.
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
        public bool TryExportPkcs8PrivateKey(Span<byte> destination, out int bytesWritten)
        {
            ThrowIfDisposed();
            return TryExportPkcs8PrivateKeyCore(destination, out bytesWritten);
        }

        /// <summary>
        ///   Exports the current key in the PKCS#8 PrivateKeyInfo format.
        /// </summary>
        /// <returns>
        ///   A byte array containing the PKCS#8 PrivateKeyInfo representation of this key.
        /// </returns>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred while exporting the key.
        /// </exception>
        public byte[] ExportPkcs8PrivateKey()
        {
            ThrowIfDisposed();
            return ExportPkcs8PrivateKeyCallback(static pkcs8 => pkcs8.ToArray());
        }

        /// <summary>
        ///   Exports the current key in a PEM-encoded representation of the PKCS#8 PrivateKeyInfo format.
        /// </summary>
        /// <returns>
        ///   A string containing the PEM-encoded representation of the PKCS#8 PrivateKeyInfo.
        /// </returns>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        /// <exception cref="CryptographicException">
        ///   An error occurred while exporting the key.
        /// </exception>
        public string ExportPkcs8PrivateKeyPem()
        {
            ThrowIfDisposed();
            return ExportPkcs8PrivateKeyCallback(static pkcs8 => PemEncoding.WriteString(PemLabels.Pkcs8PrivateKey, pkcs8));
        }

        /// <summary>
        ///   Attempts to export the current key in the PKCS#8 EncryptedPrivateKeyInfo format into a provided buffer,
        ///   using a byte-based password.
        /// </summary>
        /// <param name="passwordBytes">
        ///   The password to use when encrypting the key material.
        /// </param>
        /// <param name="pbeParameters">
        ///   The password-based encryption (PBE) parameters to use when encrypting the key material.
        /// </param>
        /// <param name="destination">
        ///   The buffer to receive the PKCS#8 EncryptedPrivateKeyInfo value.
        /// </param>
        /// <param name="bytesWritten">
        ///   When this method returns, contains the number of bytes written to the <paramref name="destination"/> buffer.
        ///   This parameter is treated as uninitialized.
        /// </param>
        /// <returns>
        ///   <see langword="true" /> if <paramref name="destination"/> was large enough to hold the result;
        ///   otherwise, <see langword="false" />.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///    <paramref name="pbeParameters"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        /// <exception cref="CryptographicException">
        ///   <para>This instance only represents a public key.</para>
        ///   <para>-or-</para>
        ///   <para>An error occurred while exporting the key.</para>
        ///   <para>-or-</para>
        ///   <para><paramref name="pbeParameters"/> does not represent a valid password-based encryption algorithm.</para>
        /// </exception>
        public bool TryExportEncryptedPkcs8PrivateKey(
            ReadOnlySpan<byte> passwordBytes,
            PbeParameters pbeParameters,
            Span<byte> destination,
            out int bytesWritten)
        {
            ArgumentNullException.ThrowIfNull(pbeParameters);
            PasswordBasedEncryption.ValidatePbeParameters(pbeParameters, ReadOnlySpan<char>.Empty, passwordBytes);
            ThrowIfDisposed();

            AsnWriter writer = ExportEncryptedPkcs8PrivateKeyCore<byte>(
                passwordBytes,
                pbeParameters,
                KeyFormatHelper.WriteEncryptedPkcs8);
            return writer.TryEncode(destination, out bytesWritten);
        }

        /// <summary>
        ///   Attempts to export the current key in the PKCS#8 EncryptedPrivateKeyInfo format into a provided buffer,
        ///   using a char-based password.
        /// </summary>
        /// <param name="password">
        ///   The password to use when encrypting the key material.
        /// </param>
        /// <param name="pbeParameters">
        ///   The password-based encryption (PBE) parameters to use when encrypting the key material.
        /// </param>
        /// <param name="destination">
        ///   The buffer to receive the PKCS#8 EncryptedPrivateKeyInfo value.
        /// </param>
        /// <param name="bytesWritten">
        ///   When this method returns, contains the number of bytes written to the <paramref name="destination"/> buffer.
        ///   This parameter is treated as uninitialized.
        /// </param>
        /// <returns>
        ///   <see langword="true" /> if <paramref name="destination"/> was large enough to hold the result;
        ///   otherwise, <see langword="false" />.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///    <paramref name="pbeParameters"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        /// <exception cref="CryptographicException">
        ///   <para>This instance only represents a public key.</para>
        ///   <para>-or-</para>
        ///   <para>An error occurred while exporting the key.</para>
        ///   <para>-or-</para>
        ///   <para><paramref name="pbeParameters"/> does not represent a valid password-based encryption algorithm.</para>
        /// </exception>
        public bool TryExportEncryptedPkcs8PrivateKey(
            ReadOnlySpan<char> password,
            PbeParameters pbeParameters,
            Span<byte> destination,
            out int bytesWritten)
        {
            ArgumentNullException.ThrowIfNull(pbeParameters);
            PasswordBasedEncryption.ValidatePbeParameters(pbeParameters, password, ReadOnlySpan<byte>.Empty);
            ThrowIfDisposed();

            AsnWriter writer = ExportEncryptedPkcs8PrivateKeyCore<char>(
                password,
                pbeParameters,
                KeyFormatHelper.WriteEncryptedPkcs8);
            return writer.TryEncode(destination, out bytesWritten);
        }

        /// <summary>
        ///   Attempts to export the current key in the PKCS#8 EncryptedPrivateKeyInfo format into a provided buffer,
        ///   using a string password.
        /// </summary>
        /// <param name="password">
        ///   The password to use when encrypting the key material.
        /// </param>
        /// <param name="pbeParameters">
        ///   The password-based encryption (PBE) parameters to use when encrypting the key material.
        /// </param>
        /// <param name="destination">
        ///   The buffer to receive the PKCS#8 EncryptedPrivateKeyInfo value.
        /// </param>
        /// <param name="bytesWritten">
        ///   When this method returns, contains the number of bytes written to the <paramref name="destination"/> buffer.
        ///   This parameter is treated as uninitialized.
        /// </param>
        /// <returns>
        ///   <see langword="true" /> if <paramref name="destination"/> was large enough to hold the result;
        ///   otherwise, <see langword="false" />.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///    <paramref name="password"/> or <paramref name="pbeParameters"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        /// <exception cref="CryptographicException">
        ///   <para>This instance only represents a public key.</para>
        ///   <para>-or-</para>
        ///   <para>An error occurred while exporting the key.</para>
        ///   <para>-or-</para>
        ///   <para><paramref name="pbeParameters"/> does not represent a valid password-based encryption algorithm.</para>
        /// </exception>
        public bool TryExportEncryptedPkcs8PrivateKey(
            string password,
            PbeParameters pbeParameters,
            Span<byte> destination,
            out int bytesWritten)
        {
            ArgumentNullException.ThrowIfNull(password);
            return TryExportEncryptedPkcs8PrivateKey(password.AsSpan(), pbeParameters, destination, out bytesWritten);
        }

        /// <summary>
        ///   Exports the current key in the PKCS#8 EncryptedPrivateKeyInfo format with a byte-based password.
        /// </summary>
        /// <param name="passwordBytes">
        ///   The password to use when encrypting the key material.
        /// </param>
        /// <param name="pbeParameters">
        ///   The password-based encryption (PBE) parameters to use when encrypting the key material.
        /// </param>
        /// <returns>
        ///   A byte array containing the PKCS#8 EncryptedPrivateKeyInfo representation of this key.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///    <paramref name="pbeParameters"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        /// <exception cref="CryptographicException">
        ///   <para>This instance only represents a public key.</para>
        ///   <para>-or-</para>
        ///   <para>An error occurred while exporting the key.</para>
        ///   <para>-or-</para>
        ///   <para><paramref name="pbeParameters"/> does not represent a valid password-based encryption algorithm.</para>
        /// </exception>
        public byte[] ExportEncryptedPkcs8PrivateKey(ReadOnlySpan<byte> passwordBytes, PbeParameters pbeParameters)
        {
            ArgumentNullException.ThrowIfNull(pbeParameters);
            PasswordBasedEncryption.ValidatePbeParameters(pbeParameters, ReadOnlySpan<char>.Empty, passwordBytes);
            ThrowIfDisposed();

            AsnWriter writer = ExportEncryptedPkcs8PrivateKeyCore<byte>(
                passwordBytes,
                pbeParameters,
                KeyFormatHelper.WriteEncryptedPkcs8);
            return writer.Encode();
        }

        /// <summary>
        ///   Exports the current key in the PKCS#8 EncryptedPrivateKeyInfo format with a char-based password.
        /// </summary>
        /// <param name="password">
        ///   The password to use when encrypting the key material.
        /// </param>
        /// <param name="pbeParameters">
        ///   The password-based encryption (PBE) parameters to use when encrypting the key material.
        /// </param>
        /// <returns>
        ///   A byte array containing the PKCS#8 EncryptedPrivateKeyInfo representation of this key.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///    <paramref name="pbeParameters"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        /// <exception cref="CryptographicException">
        ///   <para>This instance only represents a public key.</para>
        ///   <para>-or-</para>
        ///   <para>An error occurred while exporting the key.</para>
        ///   <para>-or-</para>
        ///   <para><paramref name="pbeParameters"/> does not represent a valid password-based encryption algorithm.</para>
        /// </exception>
        public byte[] ExportEncryptedPkcs8PrivateKey(ReadOnlySpan<char> password, PbeParameters pbeParameters)
        {
            ArgumentNullException.ThrowIfNull(pbeParameters);
            PasswordBasedEncryption.ValidatePbeParameters(pbeParameters, password, ReadOnlySpan<byte>.Empty);
            ThrowIfDisposed();

            AsnWriter writer = ExportEncryptedPkcs8PrivateKeyCore<char>(
                password,
                pbeParameters,
                KeyFormatHelper.WriteEncryptedPkcs8);
            return writer.Encode();
        }

        /// <summary>
        ///   Exports the current key in the PKCS#8 EncryptedPrivateKeyInfo format with a string password.
        /// </summary>
        /// <param name="password">
        ///   The password to use when encrypting the key material.
        /// </param>
        /// <param name="pbeParameters">
        ///   The password-based encryption (PBE) parameters to use when encrypting the key material.
        /// </param>
        /// <returns>
        ///   A byte array containing the PKCS#8 EncryptedPrivateKeyInfo representation of this key.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///    <paramref name="pbeParameters" /> or <paramref name="password" /> is <see langword="null" />.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        /// <exception cref="CryptographicException">
        ///   <para>This instance only represents a public key.</para>
        ///   <para>-or-</para>
        ///   <para>An error occurred while exporting the key.</para>
        ///   <para>-or-</para>
        ///   <para><paramref name="pbeParameters"/> does not represent a valid password-based encryption algorithm.</para>
        /// </exception>
        public byte[] ExportEncryptedPkcs8PrivateKey(string password, PbeParameters pbeParameters)
        {
            ArgumentNullException.ThrowIfNull(password);
            return ExportEncryptedPkcs8PrivateKey(password.AsSpan(), pbeParameters);
        }

        /// <summary>
        ///   Exports the current key in a PEM-encoded representation of the PKCS#8 EncryptedPrivateKeyInfo
        ///   format, using a byte-based password.
        /// </summary>
        /// <param name="passwordBytes">
        ///   The bytes to use as a password when encrypting the key material.
        /// </param>
        /// <param name="pbeParameters">
        ///   The password-based encryption (PBE) parameters to use when encrypting the key material.
        /// </param>
        /// <returns>
        ///   A string containing the PEM-encoded PKCS#8 EncryptedPrivateKeyInfo.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///   <paramref name="pbeParameters"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        /// <exception cref="CryptographicException">
        ///   <para><paramref name="pbeParameters"/> specifies a KDF that requires a char-based password.</para>
        ///   <para>-or-</para>
        ///   <para>This instance only represents a public key.</para>
        ///   <para>-or-</para>
        ///   <para>An error occurred while exporting the key.</para>
        /// </exception>
        public string ExportEncryptedPkcs8PrivateKeyPem(ReadOnlySpan<byte> passwordBytes, PbeParameters pbeParameters)
        {
            ArgumentNullException.ThrowIfNull(pbeParameters);
            PasswordBasedEncryption.ValidatePbeParameters(pbeParameters, ReadOnlySpan<char>.Empty, passwordBytes);
            ThrowIfDisposed();

            AsnWriter writer = ExportEncryptedPkcs8PrivateKeyCore<byte>(
                passwordBytes,
                pbeParameters,
                KeyFormatHelper.WriteEncryptedPkcs8);

            // Skip clear since the data is already encrypted.
            return Helpers.EncodeAsnWriterToPem(PemLabels.EncryptedPkcs8PrivateKey, writer, clear: false);
        }

        /// <summary>
        ///   Exports the current key in a PEM-encoded representation of the PKCS#8 EncryptedPrivateKeyInfo
        ///   format, using a char-based password.
        /// </summary>
        /// <param name="password">
        ///   The password to use when encrypting the key material.
        /// </param>
        /// <param name="pbeParameters">
        ///   The password-based encryption (PBE) parameters to use when encrypting the key material.
        /// </param>
        /// <returns>
        ///   A string containing the PEM-encoded PKCS#8 EncryptedPrivateKeyInfo.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///    <paramref name="pbeParameters"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        /// <exception cref="CryptographicException">
        ///   <para>This instance only represents a public key.</para>
        ///   <para>-or-</para>
        ///   <para>An error occurred while exporting the key.</para>
        /// </exception>
        public string ExportEncryptedPkcs8PrivateKeyPem(ReadOnlySpan<char> password, PbeParameters pbeParameters)
        {
            ArgumentNullException.ThrowIfNull(pbeParameters);
            PasswordBasedEncryption.ValidatePbeParameters(pbeParameters, password, ReadOnlySpan<byte>.Empty);
            ThrowIfDisposed();

            AsnWriter writer = ExportEncryptedPkcs8PrivateKeyCore<char>(
                password,
                pbeParameters,
                KeyFormatHelper.WriteEncryptedPkcs8);

            // Skip clear since the data is already encrypted.
            return Helpers.EncodeAsnWriterToPem(PemLabels.EncryptedPkcs8PrivateKey, writer, clear: false);
        }

        /// <summary>
        ///   Exports the current key in a PEM-encoded representation of the PKCS#8 EncryptedPrivateKeyInfo
        ///   format, using a string password.
        /// </summary>
        /// <param name="password">
        ///   The password to use when encrypting the key material.
        /// </param>
        /// <param name="pbeParameters">
        ///   The password-based encryption (PBE) parameters to use when encrypting the key material.
        /// </param>
        /// <returns>
        ///   A string containing the PEM-encoded PKCS#8 EncryptedPrivateKeyInfo.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///    <paramref name="password"/> or <paramref name="pbeParameters"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        /// <exception cref="CryptographicException">
        ///   <para>This instance only represents a public key.</para>
        ///   <para>-or-</para>
        ///   <para>An error occurred while exporting the key.</para>
        /// </exception>
        public string ExportEncryptedPkcs8PrivateKeyPem(string password, PbeParameters pbeParameters)
        {
            ArgumentNullException.ThrowIfNull(password);
            return ExportEncryptedPkcs8PrivateKeyPem(password.AsSpan(), pbeParameters);
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
        ///   When overridden in a derived class, attempts to export the current key in the PKCS#8 PrivateKeyInfo format
        ///   into the provided buffer.
        /// </summary>
        /// <param name="destination">
        ///   The buffer to receive the PKCS#8 PrivateKeyInfo value.
        /// </param>
        /// <param name="bytesWritten">
        ///   When this method returns, contains the number of bytes written to the <paramref name="destination"/> buffer.
        /// </param>
        /// <returns>
        ///   <see langword="true" /> if <paramref name="destination"/> was large enough to hold the result;
        ///   otherwise, <see langword="false" />.
        /// </returns>
        /// <exception cref="CryptographicException">
        ///   An error occurred while exporting the key.
        /// </exception>
        protected abstract bool TryExportPkcs8PrivateKeyCore(Span<byte> destination, out int bytesWritten);

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

        private TResult ExportPkcs8PrivateKeyCallback<TResult>(Func<ReadOnlySpan<byte>, TResult> func)
        {
            // A PKCS#8 X25519 PrivateKeyInfo has an ASN.1 overhead of 16 bytes, assuming no attributes.
            // Make it an even 32 and that should give a good starting point for a buffer size.
            int size = PrivateKeySizeInBytes + 32;
            byte[] buffer = CryptoPool.Rent(size);
            int written;

            while (!TryExportPkcs8PrivateKeyCore(buffer, out written))
            {
                CryptoPool.Return(buffer);
                size = checked(size * 2);
                buffer = CryptoPool.Rent(size);
            }

            if (written < 0 || written > buffer.Length)
            {
                CryptographicOperations.ZeroMemory(buffer);
                throw new CryptographicException();
            }

            TResult result = func(buffer.AsSpan(0, written));
            CryptoPool.Return(buffer, written);
            return result;
        }

        private protected bool TryExportPkcs8PrivateKeyImpl(Span<byte> destination, out int bytesWritten)
        {
            ValueAlgorithmIdentifierAsn algorithmIdentifier = new()
            {
                Algorithm = Oids.X25519,
            };

            Span<byte> privateKey = stackalloc byte[PrivateKeySizeInBytes];
            ExportPrivateKey(privateKey);

            try
            {
                AsnWriter algorithmWriter = new(AsnEncodingRules.DER);
                algorithmIdentifier.Encode(algorithmWriter);
                AsnWriter privateKeyWriter = new(AsnEncodingRules.DER);
                privateKeyWriter.WriteOctetString(privateKey);
                AsnWriter pkcs8Writer = KeyFormatHelper.WritePkcs8(algorithmWriter, privateKeyWriter);

                bool result = pkcs8Writer.TryEncode(destination, out bytesWritten);
                privateKeyWriter.Reset();
                pkcs8Writer.Reset();
                return result;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(privateKey);
            }
        }

        private AsnWriter ExportEncryptedPkcs8PrivateKeyCore<TChar>(
            ReadOnlySpan<TChar> password,
            PbeParameters pbeParameters,
            Func<ReadOnlySpan<TChar>, AsnWriter, PbeParameters, AsnWriter> encryptor)
        {
            // A PKCS#8 X25519 PrivateKeyInfo has an ASN.1 overhead of 16 bytes, assuming no attributes.
            // Make it an even 32 and that should give a good starting point for a buffer size.
            int initialSize = PrivateKeySizeInBytes + 32;
            byte[] rented = CryptoPool.Rent(initialSize);
            int written;

            while (!TryExportPkcs8PrivateKey(rented, out written))
            {
                CryptoPool.Return(rented, 0);
                rented = CryptoPool.Rent(rented.Length * 2);
            }

            AsnWriter tmp = new(AsnEncodingRules.BER, initialCapacity: written);

            try
            {
                tmp.WriteEncodedValueForCrypto(rented.AsSpan(0, written));
                return encryptor(password, tmp, pbeParameters);
            }
            finally
            {
                tmp.Reset();
                CryptoPool.Return(rented, written);
            }
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
