// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.Versioning;

namespace System.Security.Cryptography
{
    public abstract partial class Ed25519
    {
        public static new partial Ed25519 Create()
        {
            throw new PlatformNotSupportedException();
        }
    }

    public sealed class Ed25519OpenSsl : Ed25519
    {
        [UnsupportedOSPlatform("android")]
        [UnsupportedOSPlatform("browser")]
        [UnsupportedOSPlatform("ios")]
        [UnsupportedOSPlatform("tvos")]
        [UnsupportedOSPlatform("windows")]
        public Ed25519OpenSsl(SafeEvpPKeyHandle pkeyHandle) => throw new PlatformNotSupportedException();

        public override void GenerateKey() => throw new PlatformNotSupportedException();

        protected override int ExportPrivateKeyCore(Span<byte> destination) => throw new PlatformNotSupportedException();
        protected override int ExportPublicKeyCore(Span<byte> destination) => throw new PlatformNotSupportedException();
        protected override void ImportPrivateKeyCore(ReadOnlySpan<byte> privateKey) => throw new PlatformNotSupportedException();
        protected override void ImportPublicKeyCore(ReadOnlySpan<byte> publicKey) => throw new PlatformNotSupportedException();
        protected override int SignDataCore(ReadOnlySpan<byte> data, Span<byte> destination) => throw new PlatformNotSupportedException();
        protected override bool VerifyDataCore(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) => throw new PlatformNotSupportedException();
    }
}
