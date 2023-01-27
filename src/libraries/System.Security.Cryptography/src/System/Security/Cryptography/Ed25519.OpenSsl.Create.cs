// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Versioning;

namespace System.Security.Cryptography
{
    public abstract partial class Ed25519
    {
        public static new partial Ed25519 Create() => new Ed25519Wrapper(new Ed25519OpenSsl());
    }

    internal sealed class Ed25519Wrapper : Ed25519
    {
        private readonly Ed25519 _wrapped;

        internal Ed25519Wrapper(Ed25519 wrapped)
        {
            _wrapped = wrapped;
        }

        public override int KeySize
        {
            get => _wrapped.KeySize;
            set => _wrapped.KeySize = value;
        }

        public override KeySizes[] LegalKeySizes => _wrapped.LegalKeySizes;
        public override string? KeyExchangeAlgorithm => _wrapped.KeyExchangeAlgorithm;
        public override string SignatureAlgorithm => _wrapped.SignatureAlgorithm;

        public override void GenerateKey() => _wrapped.GenerateKey();
        protected override int ExportPrivateKeyCore(Span<byte> destination) => _wrapped.ExportPrivateKeyImpl(destination);
        protected override int ExportPublicKeyCore(Span<byte> destination) => _wrapped.ExportPublicKeyImpl(destination);
        protected override void ImportPrivateKeyCore(ReadOnlySpan<byte> privateKey) => _wrapped.ImportPrivateKeyImpl(privateKey);
        protected override void ImportPublicKeyCore(ReadOnlySpan<byte> publicKey) => _wrapped.ImportPublicKeyImpl(publicKey);
        protected override int SignDataCore(ReadOnlySpan<byte> data, Span<byte> destination) => _wrapped.SignDataImpl(data, destination);
        protected override bool VerifyDataCore(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) => _wrapped.VerifyDataImpl(data, signature);

        public override byte[] ExportEncryptedPkcs8PrivateKey(
            ReadOnlySpan<byte> passwordBytes,
            PbeParameters pbeParameters) =>
            _wrapped.ExportEncryptedPkcs8PrivateKey(passwordBytes, pbeParameters);

        public override byte[] ExportEncryptedPkcs8PrivateKey(
            ReadOnlySpan<char> password,
            PbeParameters pbeParameters) =>
            _wrapped.ExportEncryptedPkcs8PrivateKey(password, pbeParameters);

        public override byte[] ExportPkcs8PrivateKey() => _wrapped.ExportPkcs8PrivateKey();

        public override byte[] ExportSubjectPublicKeyInfo() => _wrapped.ExportSubjectPublicKeyInfo();

        public override void FromXmlString(string xmlString) => _wrapped.FromXmlString(xmlString);

        public override string ToXmlString(bool includePrivateParameters) =>
            _wrapped.ToXmlString(includePrivateParameters);

        public override bool TryExportSubjectPublicKeyInfo(Span<byte> destination, out int bytesWritten) =>
            _wrapped.TryExportSubjectPublicKeyInfo(destination, out bytesWritten);

        public override bool TryExportPkcs8PrivateKey(Span<byte> destination, out int bytesWritten) =>
            _wrapped.TryExportPkcs8PrivateKey(destination, out bytesWritten);

        public override bool TryExportEncryptedPkcs8PrivateKey(
            ReadOnlySpan<char> password,
            PbeParameters pbeParameters,
            Span<byte> destination,
            out int bytesWritten) =>
            _wrapped.TryExportEncryptedPkcs8PrivateKey(password, pbeParameters, destination, out bytesWritten);

        public override bool TryExportEncryptedPkcs8PrivateKey(
            ReadOnlySpan<byte> passwordBytes,
            PbeParameters pbeParameters,
            Span<byte> destination,
            out int bytesWritten) =>
            _wrapped.TryExportEncryptedPkcs8PrivateKey(passwordBytes, pbeParameters, destination, out bytesWritten);

        public override void ImportSubjectPublicKeyInfo(ReadOnlySpan<byte> source, out int bytesRead) =>
            _wrapped.ImportSubjectPublicKeyInfo(source, out bytesRead);

        public override void ImportEncryptedPkcs8PrivateKey(
            ReadOnlySpan<byte> passwordBytes,
            ReadOnlySpan<byte> source,
            out int bytesRead) =>
            _wrapped.ImportEncryptedPkcs8PrivateKey(passwordBytes, source, out bytesRead);

        public override void ImportEncryptedPkcs8PrivateKey(
            ReadOnlySpan<char> password,
            ReadOnlySpan<byte> source,
            out int bytesRead) =>
            _wrapped.ImportEncryptedPkcs8PrivateKey(password, source, out bytesRead);

        public override void ImportFromPem(ReadOnlySpan<char> input) =>
            _wrapped.ImportFromPem(input);

        public override void ImportFromEncryptedPem(ReadOnlySpan<char> input, ReadOnlySpan<char> password) =>
            _wrapped.ImportFromEncryptedPem(input, password);

        public override void ImportFromEncryptedPem(ReadOnlySpan<char> input, ReadOnlySpan<byte> passwordBytes) =>
            _wrapped.ImportFromEncryptedPem(input, passwordBytes);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _wrapped.Dispose();
            }

            base.Dispose(disposing);
        }

        public override bool Equals(object? obj) => _wrapped.Equals(obj);
        public override int GetHashCode() => _wrapped.GetHashCode();
        public override string ToString() => _wrapped.ToString()!;
    }
}
