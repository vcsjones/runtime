// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if NET

using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace System.IO.Hashing
{
    /// <summary>
    /// Provides helper methods for computing CRC polynomial folding constants
    /// used in SIMD-accelerated CRC computation.
    /// </summary>
    /// <remarks>
    /// The folding constants are values of x^n mod P(x) in GF(2) for various powers n.
    /// These are used in the Intel PCLMULQDQ-based CRC algorithm described in
    /// "Fast CRC Computation for Generic Polynomials Using PCLMULQDQ Instruction" (December 2009).
    /// </remarks>
    internal static class CrcPolynomialHelper
    {
        /// <summary>
        /// Computes x^<paramref name="power"/> mod P(x) in GF(2), where P(x) is a polynomial
        /// of degree <paramref name="polyDeg"/> represented by <paramref name="poly"/>.
        /// </summary>
        /// <param name="poly">
        /// The polynomial with the explicit leading bit set.
        /// For CRC-32 with polynomial 0x04C11DB7, pass 0x104C11DB7.
        /// For CRC-64 with polynomial 0x42F0E1EBA9EA3693, pass 0x142F0E1EBA9EA3693 (as UInt128).
        /// </param>
        /// <param name="polyDeg">The degree of the polynomial (32 for CRC-32, 64 for CRC-64).</param>
        /// <param name="power">The power of x to compute (e.g. 4*128+64 for k1).</param>
        /// <returns>The result of x^power mod P(x), fitting in a ulong.</returns>
        internal static ulong ComputeFoldingConstant(UInt128 poly, int polyDeg, int power)
        {
            Debug.Assert(polyDeg is 32 or 64);
            Debug.Assert(power > 0);

            // We need enough bits to hold x^power before reducing.
            // x^power has one bit at position 'power', so we need power+1 bits.
            // Maximum power for 4-way CRC-32 fold: 4*128+64 = 576, so 577 bits = 10 ulongs.
            // Maximum power for 4-way CRC-64 fold: 4*128+64 = 576, so 577+32 bits = 10 ulongs.
            UInt640 value = default;
            value.SetBit(power);

            // Reduce: while degree(value) >= polyDeg, XOR with poly shifted appropriately
            int valueDegree = value.Degree;

            while (valueDegree >= polyDeg)
            {
                int shift = valueDegree - polyDeg;
                UInt640 polyShifted = default;
                polyShifted.SetFromUInt128(poly);
                polyShifted.ShiftLeft(shift);
                value.Xor(ref polyShifted);
                valueDegree = value.Degree;
            }

            return value.ToUInt64();
        }

        /// <summary>
        /// Computes the Barrett reduction constant μ = ⌊x^(2*polyDeg) / P(x)⌋ in GF(2).
        /// </summary>
        /// <param name="poly">The polynomial with the explicit leading bit set.</param>
        /// <param name="polyDeg">The degree of the polynomial (32 or 64).</param>
        /// <returns>The Barrett constant μ.</returns>
        internal static ulong ComputeBarrettConstant(UInt128 poly, int polyDeg)
        {
            Debug.Assert(polyDeg is 32 or 64);

            // We compute x^(2*polyDeg) / P(x) = quotient in GF(2) polynomial division.
            // x^(2*polyDeg) has bit at position 2*polyDeg.
            UInt640 dividend = default;
            dividend.SetBit(2 * polyDeg);

            UInt640 quotient = default;

            int dividendDegree = dividend.Degree;

            while (dividendDegree >= polyDeg)
            {
                int shift = dividendDegree - polyDeg;
                quotient.SetBit(shift);
                UInt640 polyShifted = default;
                polyShifted.SetFromUInt128(poly);
                polyShifted.ShiftLeft(shift);
                dividend.Xor(ref polyShifted);
                dividendDegree = dividend.Degree;
            }

            return quotient.ToUInt64();
        }

        /// <summary>
        /// A 640-bit unsigned integer type for GF(2) polynomial arithmetic.
        /// Represented as 10 ulongs in little-endian order.
        /// </summary>
        [InlineArray(Length)]
        internal struct UInt640
        {
            internal const int Length = 10;
            private ulong _element;

            /// <summary>Gets the degree (position of highest set bit) of this value. Returns -1 if zero.</summary>
            internal readonly int Degree
            {
                get
                {
                    for (int i = Length - 1; i >= 0; i--)
                    {
                        ulong word = this[i];
                        if (word != 0)
                        {
                            return (i * 64) + (63 - System.Numerics.BitOperations.LeadingZeroCount(word));
                        }
                    }

                    return -1;
                }
            }

            /// <summary>Sets a single bit at the given position.</summary>
            internal void SetBit(int position)
            {
                int wordIndex = position / 64;
                int bitIndex = position % 64;
                Debug.Assert(wordIndex < Length);
                this[wordIndex] |= 1UL << bitIndex;
            }

            /// <summary>Initializes from a UInt128 value.</summary>
            internal void SetFromUInt128(UInt128 value)
            {
                this[0] = (ulong)value;
                this[1] = (ulong)(value >> 64);
            }

            /// <summary>Shifts all bits left by the given amount.</summary>
            internal void ShiftLeft(int shift)
            {
                Debug.Assert(shift >= 0);
                if (shift == 0)
                {
                    return;
                }

                int wordShift = shift / 64;
                int bitShift = shift % 64;

                // Shift words
                if (wordShift > 0)
                {
                    for (int i = Length - 1; i >= 0; i--)
                    {
                        this[i] = i >= wordShift ? this[i - wordShift] : 0;
                    }
                }

                // Shift bits within words
                if (bitShift > 0)
                {
                    for (int i = Length - 1; i > 0; i--)
                    {
                        this[i] = (this[i] << bitShift) | (this[i - 1] >> (64 - bitShift));
                    }

                    this[0] <<= bitShift;
                }
            }

            /// <summary>XORs this value with another.</summary>
            internal void Xor(ref UInt640 other)
            {
                for (int i = 0; i < Length; i++)
                {
                    this[i] ^= other[i];
                }
            }

            /// <summary>Extracts the low 64 bits.</summary>
            internal readonly ulong ToUInt64() => this[0];

        }
    }
}

#endif
