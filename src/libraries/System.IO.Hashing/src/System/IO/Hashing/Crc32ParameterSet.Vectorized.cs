// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if NET

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using static System.IO.Hashing.VectorHelper;

namespace System.IO.Hashing
{
    public partial class Crc32ParameterSet
    {
        private sealed partial class ReflectedTableBasedCrc32
        {
            // For reflected CRC-32, the folding constants are computed as:
            //   constant = bit_reverse(x^power mod P(x), 33)
            // where P(x) is the NORMAL (unreflected) polynomial with explicit leading x^32 bit.
            // The Barrett reduction vector stores [reflect(P, 33), reflect(mu, 33)]
            // where mu = floor(x^64 / P(x)).
            private Vector128<ulong> _k1k2;
            private Vector128<ulong> _k3k4;
            private ulong _k5;
            private ulong _k6;
            private Vector128<ulong> _barrettConstants;
            private bool _canVectorize;

            partial void InitializeVectorizedConstants()
            {
                if (!BitConverter.IsLittleEndian || !VectorHelper.IsSupported)
                {
                    return;
                }

                UInt128 fullPoly = (UInt128)1 << 32 | Polynomial;

                _k1k2 = Vector128.Create(
                    ReflectConstant(CrcPolynomialHelper.ComputeFoldingConstant(fullPoly, 32, 4 * 128 + 32), 33),
                    ReflectConstant(CrcPolynomialHelper.ComputeFoldingConstant(fullPoly, 32, 4 * 128 - 32), 33));

                ulong k3 = ReflectConstant(CrcPolynomialHelper.ComputeFoldingConstant(fullPoly, 32, 128 + 32), 33);
                ulong k4 = ReflectConstant(CrcPolynomialHelper.ComputeFoldingConstant(fullPoly, 32, 128 - 32), 33);
                _k3k4 = Vector128.Create(k3, k4);

                _k5 = k4;
                _k6 = ReflectConstant(CrcPolynomialHelper.ComputeFoldingConstant(fullPoly, 32, 64), 33);

                ulong mu = CrcPolynomialHelper.ComputeBarrettConstant(fullPoly, 32);
                _barrettConstants = Vector128.Create(
                    ReflectConstant((ulong)fullPoly, 33),
                    ReflectConstant(mu, 33));

                _canVectorize = true;
            }

            partial void UpdateVectorized(ref uint crc, ReadOnlySpan<byte> source, ref int bytesConsumed)
            {
                if (!_canVectorize || source.Length < Vector128<byte>.Count)
                {
                    return;
                }

                crc = UpdateVectorizedCore(crc, source, out bytesConsumed);
            }

            [MethodImpl(MethodImplOptions.NoInlining)]
            private uint UpdateVectorizedCore(uint crc, ReadOnlySpan<byte> source, out int bytesConsumed)
            {
                ref byte srcRef = ref MemoryMarshal.GetReference(source);
                int length = source.Length;

                Vector128<ulong> x1;
                Vector128<ulong> x2;

                if (length >= Vector128<byte>.Count * 4)
                {
                    x1 = Vector128.LoadUnsafe(ref srcRef).AsUInt64();
                    x2 = Vector128.LoadUnsafe(ref srcRef, 16).AsUInt64();
                    Vector128<ulong> x3 = Vector128.LoadUnsafe(ref srcRef, 32).AsUInt64();
                    Vector128<ulong> x4 = Vector128.LoadUnsafe(ref srcRef, 48).AsUInt64();

                    srcRef = ref Unsafe.Add(ref srcRef, Vector128<byte>.Count * 4);
                    length -= Vector128<byte>.Count * 4;

                    x1 ^= Vector128.CreateScalar(crc).AsUInt64();

                    while (length >= Vector128<byte>.Count * 4)
                    {
                        Vector128<ulong> y5 = Vector128.LoadUnsafe(ref srcRef).AsUInt64();
                        Vector128<ulong> y6 = Vector128.LoadUnsafe(ref srcRef, 16).AsUInt64();
                        Vector128<ulong> y7 = Vector128.LoadUnsafe(ref srcRef, 32).AsUInt64();
                        Vector128<ulong> y8 = Vector128.LoadUnsafe(ref srcRef, 48).AsUInt64();

                        x1 = FoldPolynomialPair(y5, x1, _k1k2);
                        x2 = FoldPolynomialPair(y6, x2, _k1k2);
                        x3 = FoldPolynomialPair(y7, x3, _k1k2);
                        x4 = FoldPolynomialPair(y8, x4, _k1k2);

                        srcRef = ref Unsafe.Add(ref srcRef, Vector128<byte>.Count * 4);
                        length -= Vector128<byte>.Count * 4;
                    }

                    x1 = FoldPolynomialPair(x2, x1, _k3k4);
                    x1 = FoldPolynomialPair(x3, x1, _k3k4);
                    x1 = FoldPolynomialPair(x4, x1, _k3k4);
                }
                else
                {
                    x1 = Vector128.LoadUnsafe(ref srcRef).AsUInt64();
                    x1 ^= Vector128.CreateScalar(crc).AsUInt64();

                    srcRef = ref Unsafe.Add(ref srcRef, Vector128<byte>.Count);
                    length -= Vector128<byte>.Count;
                }

                while (length >= Vector128<byte>.Count)
                {
                    x1 = FoldPolynomialPair(Vector128.LoadUnsafe(ref srcRef).AsUInt64(), x1, _k3k4);

                    srcRef = ref Unsafe.Add(ref srcRef, Vector128<byte>.Count);
                    length -= Vector128<byte>.Count;
                }

                // Fold 128 bits to 64 bits.
                Vector128<ulong> bitmask = Vector128.Create(~0, 0, ~0, 0).AsUInt64();
                x1 = ShiftRightBytesInVector(x1, 8) ^
                     CarrylessMultiplyLower(x1, Vector128.CreateScalar(_k5));
                x1 = CarrylessMultiplyLower(x1 & bitmask, Vector128.CreateScalar(_k6)) ^
                     ShiftRightBytesInVector(x1, 4);

                // Barrett reduction to 32 bits.
                x2 = CarrylessMultiplyLeftLowerRightUpper(x1 & bitmask, _barrettConstants) & bitmask;
                x2 = CarrylessMultiplyLower(x2, _barrettConstants);
                x1 ^= x2;

                bytesConsumed = source.Length - length;

                return x1.AsUInt32().GetElement(1);
            }
        }

        private sealed partial class ForwardTableBasedCrc32
        {
            // For forward CRC-32, the folding constants are computed directly:
            //   constant = x^power mod P(x)
            // Data is loaded with byte-reversal (MSB first), CRC placed in upper bits.
            // The 128→64 reduction uses FoldPolynomialPair with [x^32, x^96] to embed
            // the required x^32 shift factor, then one more fold with x^64, then Barrett.
            private Vector128<ulong> _k1k2;
            private Vector128<ulong> _k3k4;
            private Vector128<ulong> _foldConstants;
            private ulong _k5;
            private ulong _mu;
            private ulong _polyFull;
            private bool _canVectorize;

            partial void InitializeVectorizedConstants()
            {
                if (!BitConverter.IsLittleEndian || !VectorHelper.IsSupported)
                {
                    return;
                }

                UInt128 fullPoly = (UInt128)1 << 32 | Polynomial;

                _k1k2 = Vector128.Create(
                    CrcPolynomialHelper.ComputeFoldingConstant(fullPoly, 32, 4 * 128),
                    CrcPolynomialHelper.ComputeFoldingConstant(fullPoly, 32, 4 * 128 + 64));

                ulong k3 = CrcPolynomialHelper.ComputeFoldingConstant(fullPoly, 32, 128);
                ulong k4 = CrcPolynomialHelper.ComputeFoldingConstant(fullPoly, 32, 128 + 64);
                _k3k4 = Vector128.Create(k3, k4);

                // Constants for 128→~96 fold: [x^32 mod P, x^96 mod P]
                // This computes L*x^32 + H*x^96 = x^32*(H*x^64 + L) = x^32*V (mod P),
                // which embeds the CRC's required x^32 shift factor.
                _foldConstants = Vector128.Create(
                    CrcPolynomialHelper.ComputeFoldingConstant(fullPoly, 32, 32),
                    CrcPolynomialHelper.ComputeFoldingConstant(fullPoly, 32, 96));

                _k5 = CrcPolynomialHelper.ComputeFoldingConstant(fullPoly, 32, 64);
                _mu = CrcPolynomialHelper.ComputeBarrettConstant(fullPoly, 32);
                _polyFull = (ulong)fullPoly;

                _canVectorize = true;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static Vector128<ulong> LoadReversed(ref byte source, nuint elementOffset)
            {
                Vector128<byte> vector = Vector128.LoadUnsafe(ref source, elementOffset);

                if (BitConverter.IsLittleEndian)
                {
                    vector = Vector128.Shuffle(vector,
                        Vector128.Create((byte)0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08,
                                               0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00));
                }

                return vector.AsUInt64();
            }

            partial void UpdateVectorized(ref uint crc, ReadOnlySpan<byte> source, ref int bytesConsumed)
            {
                if (!_canVectorize || source.Length < Vector128<byte>.Count)
                {
                    return;
                }

                crc = UpdateVectorizedCore(crc, source, out bytesConsumed);
            }

            [MethodImpl(MethodImplOptions.NoInlining)]
            private uint UpdateVectorizedCore(uint crc, ReadOnlySpan<byte> source, out int bytesConsumed)
            {
                ref byte srcRef = ref MemoryMarshal.GetReference(source);
                int length = source.Length;

                Vector128<ulong> x1;

                if (length >= Vector128<byte>.Count * 4)
                {
                    x1 = LoadReversed(ref srcRef, 0);
                    Vector128<ulong> x2 = LoadReversed(ref srcRef, 16);
                    Vector128<ulong> x3 = LoadReversed(ref srcRef, 32);
                    Vector128<ulong> x4 = LoadReversed(ref srcRef, 48);

                    srcRef = ref Unsafe.Add(ref srcRef, Vector128<byte>.Count * 4);
                    length -= Vector128<byte>.Count * 4;

                    x1 ^= ShiftLowerToUpper(Vector128.CreateScalar((ulong)crc << 32));

                    while (length >= Vector128<byte>.Count * 4)
                    {
                        Vector128<ulong> y5 = LoadReversed(ref srcRef, 0);
                        Vector128<ulong> y6 = LoadReversed(ref srcRef, 16);
                        Vector128<ulong> y7 = LoadReversed(ref srcRef, 32);
                        Vector128<ulong> y8 = LoadReversed(ref srcRef, 48);

                        x1 = FoldPolynomialPair(y5, x1, _k1k2);
                        x2 = FoldPolynomialPair(y6, x2, _k1k2);
                        x3 = FoldPolynomialPair(y7, x3, _k1k2);
                        x4 = FoldPolynomialPair(y8, x4, _k1k2);

                        srcRef = ref Unsafe.Add(ref srcRef, Vector128<byte>.Count * 4);
                        length -= Vector128<byte>.Count * 4;
                    }

                    x1 = FoldPolynomialPair(x2, x1, _k3k4);
                    x1 = FoldPolynomialPair(x3, x1, _k3k4);
                    x1 = FoldPolynomialPair(x4, x1, _k3k4);
                }
                else
                {
                    x1 = LoadReversed(ref srcRef, 0);
                    x1 ^= ShiftLowerToUpper(Vector128.CreateScalar((ulong)crc << 32));

                    srcRef = ref Unsafe.Add(ref srcRef, Vector128<byte>.Count);
                    length -= Vector128<byte>.Count;
                }

                while (length >= Vector128<byte>.Count)
                {
                    x1 = FoldPolynomialPair(LoadReversed(ref srcRef, 0), x1, _k3k4);

                    srcRef = ref Unsafe.Add(ref srcRef, Vector128<byte>.Count);
                    length -= Vector128<byte>.Count;
                }

                // Fold 128→~96 bits using FoldPolynomialPair with [x^32 mod P, x^96 mod P].
                // This computes x^32*V (mod P), embedding the x^32 shift factor
                // that forward CRC requires (CRC = M(x)*x^32 mod P).
                x1 = FoldPolynomialPair(Vector128<ulong>.Zero, x1, _foldConstants);

                // Fold ~96→64 bits: the result has at most ~95 bits (32-bit constants × 64-bit data).
                // Fold the upper bits down using x^64 mod P.
                Vector128<ulong> lowerMask = Vector128.Create(~0UL, 0UL);
                x1 = CarrylessMultiplyLeftUpperRightLower(x1, Vector128.CreateScalar(_k5)) ^ (x1 & lowerMask);

                // Barrett reduction: 64→32 bits.
                // t = V >> 32, q = (t * μ) >> 32, r = V ^ (q * P)
                Vector128<ulong> bitmask = Vector128.Create(~0, 0, ~0, 0).AsUInt64();
                Vector128<ulong> temp = x1;
                x1 = ShiftRightBytesInVector(x1, 4) & bitmask;
                x1 = CarrylessMultiplyLower(x1, Vector128.CreateScalar(_mu));
                x1 = ShiftRightBytesInVector(x1, 4) & bitmask;
                x1 = CarrylessMultiplyLower(x1, Vector128.CreateScalar(_polyFull));
                x1 ^= temp;

                bytesConsumed = source.Length - length;

                return x1.AsUInt32().GetElement(0);
            }
        }

        private static ulong ReflectConstant(ulong value, int width)
        {
            ulong result = 0;
            for (int i = 0; i < width; i++)
            {
                if (((value >> i) & 1) != 0)
                {
                    result |= 1UL << (width - 1 - i);
                }
            }

            return result;
        }
    }
}

#endif
