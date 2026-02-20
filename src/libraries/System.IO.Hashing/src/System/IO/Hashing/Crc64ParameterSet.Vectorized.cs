// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if NET

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using static System.IO.Hashing.VectorHelper;

namespace System.IO.Hashing
{
    public partial class Crc64ParameterSet
    {
        private sealed partial class ForwardTableBasedCrc64
        {
            // For forward CRC-64, constants are computed directly:
            //   constant = x^power mod P(x)
            // Data is byte-reversed on load. CRC placed in upper bits.
            private Vector128<ulong> _k1k2;
            private Vector128<ulong> _k3k4;
            private ulong _k5;
            private Vector128<ulong> _barrettConstants;
            private bool _canVectorize;

            partial void InitializeVectorizedConstants()
            {
                if (!BitConverter.IsLittleEndian || !VectorHelper.IsSupported)
                {
                    return;
                }

                UInt128 fullPoly = (UInt128)1 << 64 | Polynomial;

                _k1k2 = Vector128.Create(
                    CrcPolynomialHelper.ComputeFoldingConstant(fullPoly, 64, 4 * 128),
                    CrcPolynomialHelper.ComputeFoldingConstant(fullPoly, 64, 4 * 128 + 64));

                ulong k3 = CrcPolynomialHelper.ComputeFoldingConstant(fullPoly, 64, 128);
                ulong k4 = CrcPolynomialHelper.ComputeFoldingConstant(fullPoly, 64, 128 + 64);
                _k3k4 = Vector128.Create(k3, k4);

                _k5 = k3;

                ulong mu = CrcPolynomialHelper.ComputeBarrettConstant(fullPoly, 64);
                _barrettConstants = Vector128.Create(mu, (ulong)fullPoly);

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

            partial void UpdateVectorized(ref ulong crc, ReadOnlySpan<byte> source, ref int bytesConsumed)
            {
                if (!_canVectorize || source.Length < Vector128<byte>.Count)
                {
                    return;
                }

                crc = UpdateVectorizedCore(crc, source, out bytesConsumed);
            }

            [MethodImpl(MethodImplOptions.NoInlining)]
            private ulong UpdateVectorizedCore(ulong crc, ReadOnlySpan<byte> source, out int bytesConsumed)
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

                    x1 ^= ShiftLowerToUpper(Vector128.CreateScalar(crc));

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
                    x1 ^= ShiftLowerToUpper(Vector128.CreateScalar(crc));

                    srcRef = ref Unsafe.Add(ref srcRef, Vector128<byte>.Count);
                    length -= Vector128<byte>.Count;
                }

                while (length >= Vector128<byte>.Count)
                {
                    x1 = FoldPolynomialPair(LoadReversed(ref srcRef, 0), x1, _k3k4);

                    srcRef = ref Unsafe.Add(ref srcRef, Vector128<byte>.Count);
                    length -= Vector128<byte>.Count;
                }

                // Fold 128→64 bits (forward: fold upper into lower)
                x1 = CarrylessMultiplyLeftUpperRightLower(x1, Vector128.CreateScalar(_k5)) ^
                     ShiftLowerToUpper(x1);

                // Barrett reduction
                Vector128<ulong> temp = x1;
                x1 = CarrylessMultiplyLeftUpperRightLower(x1, _barrettConstants) ^
                     (x1 & Vector128.Create(0UL, ~0UL));
                x1 = CarrylessMultiplyUpper(x1, _barrettConstants);
                x1 ^= temp;

                bytesConsumed = source.Length - length;

                return x1.GetElement(0);
            }
        }

    }
}

#endif
