// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Xunit;

namespace System.Security.Cryptography.Tests
{
    [ConditionalClass(typeof(Ed25519), nameof(Ed25519.IsSupported))]
    public sealed class Ed25519ImplementationTests : Ed25519BaseTests
    {
        public override Ed25519 GenerateKey() => Ed25519.GenerateKey();

        public override Ed25519 ImportPrivateKey(ReadOnlySpan<byte> source) =>
            Ed25519.ImportPrivateKey(source);

        public override Ed25519 ImportPublicKey(ReadOnlySpan<byte> source) =>
            Ed25519.ImportPublicKey(source);
    }

    public static class Ed25519ImplementationSupportedTests
    {
        [Fact]
        public static void IsSupported_AgreesWithPlatform()
        {
            Assert.Equal(PlatformDetection.IsOpenSslSupported, Ed25519.IsSupported);
        }
    }
}
