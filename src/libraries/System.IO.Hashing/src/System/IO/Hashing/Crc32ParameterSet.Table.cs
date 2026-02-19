// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
#if NET
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using static System.IO.Hashing.VectorHelper;
#endif

namespace System.IO.Hashing
{
    public partial class Crc32ParameterSet
    {
        private static uint[] GenerateLookupTable(uint polynomial, bool reflectInput)
        {
            uint[] table = new uint[256];

            if (!reflectInput)
            {
                uint crc = 0x80000000u;

                for (int i = 1; i < 256; i <<= 1)
                {
                    if ((crc & 0x80000000u) != 0)
                    {
                        crc = (crc << 1) ^ polynomial;
                    }
                    else
                    {
                        crc <<= 1;
                    }

                    for (int j = 0; j < i; j++)
                    {
                        table[i + j] = crc ^ table[j];
                    }
                }
            }
            else
            {
                for (int i = 1; i < 256; i++)
                {
                    uint r = ReverseBits((uint)i);

                    const uint LastBit = 0x80000000u;

                    for (int j = 0; j < 8; j++)
                    {
                        if ((r & LastBit) != 0)
                        {
                            r = (r << 1) ^ polynomial;
                        }
                        else
                        {
                            r <<= 1;
                        }
                    }

                    table[i] = ReverseBits(r);
                }
            }

            return table;
        }

        private sealed class ReflectedTableBasedCrc32 : Crc32ParameterSet
        {
            private readonly uint[] _lookupTable;
#if NET
            private readonly Vector128<ulong> _k1k2;
            private readonly Vector128<ulong> _k3k4;
            private readonly ulong _k5;
            private readonly ulong _k4;
            private readonly Vector128<ulong> _muPoly;
#endif

            internal ReflectedTableBasedCrc32(uint polynomial, uint initialValue, uint finalXorValue)
                : base(polynomial, initialValue, finalXorValue, reflectValues: true)
            {
                _lookupTable = GenerateLookupTable(polynomial, reflectInput: true);
#if NET
                CrcPolynomialHelper.ComputeReflectedCrc32Constants(
                    polynomial,
                    out _k1k2,
                    out _k3k4,
                    out _k5,
                    out _k4,
                    out _muPoly);
#endif
            }

            internal override uint Update(uint value, ReadOnlySpan<byte> source)
            {
#if NET
                if (BitConverter.IsLittleEndian
                    && VectorHelper.IsSupported
                    && source.Length >= Vector128<byte>.Count)
                {
                    return UpdateVectorized(value, source);
                }
#endif
                return UpdateScalar(value, source);
            }

            private uint UpdateScalar(uint value, ReadOnlySpan<byte> source)
            {
                uint[] lookupTable = _lookupTable;
                uint crc = value;

                Debug.Assert(lookupTable.Length == 256);

                foreach (byte dataByte in source)
                {
                    byte idx = (byte)(crc ^ dataByte);
                    crc = lookupTable[idx] ^ (crc >> 8);
                }

                return crc;
            }

#if NET
            [MethodImpl(MethodImplOptions.NoInlining)]
            private uint UpdateVectorized(uint crc, ReadOnlySpan<byte> source)
            {
                ref byte srcRef = ref MemoryMarshal.GetReference(source);
                int length = source.Length;

                Vector128<ulong> x1;
                Vector128<ulong> x2;

                if (length >= Vector128<byte>.Count * 8)
                {
                    x1 = Vector128.LoadUnsafe(ref srcRef).AsUInt64();
                    x2 = Vector128.LoadUnsafe(ref srcRef, 16).AsUInt64();
                    Vector128<ulong> x3 = Vector128.LoadUnsafe(ref srcRef, 32).AsUInt64();
                    Vector128<ulong> x4 = Vector128.LoadUnsafe(ref srcRef, 48).AsUInt64();

                    srcRef = ref Unsafe.Add(ref srcRef, Vector128<byte>.Count * 4);
                    length -= Vector128<byte>.Count * 4;

                    x1 ^= Vector128.CreateScalar(crc).AsUInt64();

                    // Parallel fold blocks of 64, if any.
                    do
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
                    } while (length >= Vector128<byte>.Count * 4);

                    // Fold into 128-bits.
                    x1 = FoldPolynomialPair(x2, x1, _k3k4);
                    x1 = FoldPolynomialPair(x3, x1, _k3k4);
                    x1 = FoldPolynomialPair(x4, x1, _k3k4);
                }
                else
                {
                    Debug.Assert(length >= 16);

                    x1 = Vector128.LoadUnsafe(ref srcRef).AsUInt64();
                    x1 ^= Vector128.CreateScalar(crc).AsUInt64();

                    srcRef = ref Unsafe.Add(ref srcRef, Vector128<byte>.Count);
                    length -= Vector128<byte>.Count;
                }

                // Single fold blocks of 16, if any.
                while (length >= Vector128<byte>.Count)
                {
                    x1 = FoldPolynomialPair(Vector128.LoadUnsafe(ref srcRef).AsUInt64(), x1, _k3k4);

                    srcRef = ref Unsafe.Add(ref srcRef, Vector128<byte>.Count);
                    length -= Vector128<byte>.Count;
                }

                // Fold 128 bits to 64 bits.
                Vector128<ulong> bitmask = Vector128.Create(~0, 0, ~0, 0).AsUInt64();
                x1 = ShiftRightBytesInVector(x1, 8) ^
                     CarrylessMultiplyLower(x1, Vector128.CreateScalar(_k4));
                x1 = CarrylessMultiplyLower(x1 & bitmask, Vector128.CreateScalar(_k5)) ^
                     ShiftRightBytesInVector(x1, 4);

                // Barrett reduction to 32 bits.
                x2 = CarrylessMultiplyLeftLowerRightUpper(x1 & bitmask, _muPoly) & bitmask;
                x2 = CarrylessMultiplyLower(x2, _muPoly);
                x1 ^= x2;

                uint result = x1.AsUInt32().GetElement(1);
                return length > 0
                    ? UpdateScalar(result, MemoryMarshal.CreateReadOnlySpan(ref srcRef, length))
                    : result;
            }
#endif
        }

        private sealed class ForwardTableBasedCrc32 : Crc32ParameterSet
        {
            private readonly uint[] _lookupTable;

            internal ForwardTableBasedCrc32(uint polynomial, uint initialValue, uint finalXorValue)
                : base(polynomial, initialValue, finalXorValue, reflectValues: false)
            {
                _lookupTable = GenerateLookupTable(polynomial, reflectInput: false);
            }

            internal override uint Update(uint value, ReadOnlySpan<byte> source)
            {
                uint[] lookupTable = _lookupTable;
                uint crc = value;

                Debug.Assert(lookupTable.Length == 256);

                foreach (byte dataByte in source)
                {
                    byte idx = (byte)((crc >> 24) ^ dataByte);
                    crc = lookupTable[idx] ^ (crc << 8);
                }

                return crc;
            }
        }
    }
}
