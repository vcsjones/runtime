// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Apple;

#pragma warning disable CS3016 // Arrays as attribute arguments are not CLS Compliant

internal static partial class Interop
{
    internal static partial class AppleCrypto
    {
        [LibraryImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_DigestFree")]
        internal static partial void DigestFree(IntPtr handle);

        [LibraryImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_DigestCreate")]
        internal static partial SafeDigestCtxHandle DigestCreate(PAL_HashAlgorithm algorithm, out int cbDigest);

        internal static int DigestUpdate(SafeDigestCtxHandle ctx, ReadOnlySpan<byte> data) =>
            DigestUpdate(ctx, ref MemoryMarshal.GetReference(data), data.Length);

        [LibraryImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_DigestUpdate")]
        private static partial int DigestUpdate(SafeDigestCtxHandle ctx, ref byte pbData, int cbData);

        internal static int DigestFinal(SafeDigestCtxHandle ctx, Span<byte> output) =>
            DigestFinal(ctx, ref MemoryMarshal.GetReference(output), output.Length);

        [LibraryImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_DigestFinal")]
        private static partial int DigestFinal(SafeDigestCtxHandle ctx, ref byte pbOutput, int cbOutput);

        internal static int DigestCurrent(SafeDigestCtxHandle ctx, Span<byte> output) =>
            DigestCurrent(ctx, ref MemoryMarshal.GetReference(output), output.Length);

        [LibraryImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_DigestCurrent")]
        private static partial int DigestCurrent(SafeDigestCtxHandle ctx, ref byte pbOutput, int cbOutput);

        [LibraryImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_DigestOneShot")]
        internal static unsafe partial int DigestOneShot(PAL_HashAlgorithm algorithm, byte* pbData, int cbData, byte* pbOutput, int cbOutput, int* cbDigest);

        [LibraryImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_DigestReset")]
        internal static partial int DigestReset(SafeDigestCtxHandle ctx);

        [LibraryImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_DigestClone")]
        internal static partial SafeDigestCtxHandle DigestClone(SafeDigestCtxHandle ctx);

        [LibraryImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_Sha3DigestCreate")]
        [UnmanagedCallConv(CallConvs = [ typeof(CallConvSwift) ])]
        internal static partial SafeSha3DigestHandle Sha3DigestCreate(PAL_HashAlgorithm algorithm, out int cbDigest);

        [LibraryImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_Sha3DigestFinal")]
        private static partial int Sha3DigestFinal(SafeSha3DigestHandle ctx, ref byte pbOutput, int cbOutput);

        internal static int Sha3DigestFinal(SafeSha3DigestHandle ctx, Span<byte> output) =>
            Sha3DigestFinal(ctx, ref MemoryMarshal.GetReference(output), output.Length);

        [LibraryImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_Sha3DigestFree")]
        [UnmanagedCallConv(CallConvs = [ typeof(CallConvSwift) ])]
        internal static partial void Sha3DigestFree(IntPtr ptr);

        [LibraryImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_Sha3DigestOneShot")]
        [UnmanagedCallConv(CallConvs = [ typeof(CallConvSwift) ])]
        internal static unsafe partial int Sha3DigestOneShot(PAL_HashAlgorithm algorithm, byte* pbData, int cbData, byte* pbOutput, int cbOutput, int* cbDigest);

        [LibraryImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_Sha3DigestUpdate")]
        [UnmanagedCallConv(CallConvs = [ typeof(CallConvSwift) ])]
        private static partial int Sha3DigestUpdate(SafeSha3DigestHandle ctx, ref byte pbData, int cbData);

        internal static int Sha3DigestUpdate(SafeSha3DigestHandle ctx, ReadOnlySpan<byte> data) =>
            Sha3DigestUpdate(ctx, ref MemoryMarshal.GetReference(data), data.Length);

        [LibraryImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_Sha3DigestReset")]
        [UnmanagedCallConv(CallConvs = [ typeof(CallConvSwift) ])]
        internal static partial int Sha3DigestReset(SafeSha3DigestHandle ctx);

        internal static int Sha3DigestCurrent(SafeSha3DigestHandle ctx, Span<byte> output) =>
            Sha3DigestCurrent(ctx, ref MemoryMarshal.GetReference(output), output.Length);

        [LibraryImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_Sha3DigestCurrent")]
        [UnmanagedCallConv(CallConvs = [ typeof(CallConvSwift) ])]
        private static partial int Sha3DigestCurrent(SafeSha3DigestHandle ctx, ref byte pbOutput, int cbOutput);
    }
}

namespace System.Security.Cryptography.Apple
{
    internal sealed class SafeDigestCtxHandle : SafeHandle
    {
        public SafeDigestCtxHandle()
            : base(IntPtr.Zero, ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle()
        {
            Interop.AppleCrypto.DigestFree(handle);
            SetHandle(IntPtr.Zero);
            return true;
        }

        public override bool IsInvalid => handle == IntPtr.Zero;
    }

    internal sealed class SafeSha3DigestHandle : SafeHandle
    {
        public SafeSha3DigestHandle() : base(IntPtr.Zero, ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle()
        {
            Interop.AppleCrypto.Sha3DigestFree(handle);
            SetHandle(IntPtr.Zero);
            return true;
        }

        public override bool IsInvalid => handle == 0;
    }
}
