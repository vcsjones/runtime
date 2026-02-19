// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if NET
using System.Runtime.Intrinsics;

namespace System.IO.Hashing
{
    /// <summary>
    /// Provides GF(2) polynomial arithmetic for computing CRC folding constants
    /// used by the PCLMULQDQ/PMULL vectorized CRC algorithm.
    /// </summary>
    internal static class CrcPolynomialHelper
    {
        /// <summary>
        /// Computes x^<paramref name="power"/> mod <paramref name="poly"/> in GF(2).
        /// </summary>
        /// <param name="poly">
        /// The polynomial divisor, including the leading x^degree term.
        /// For a CRC-32 polynomial 0x04C11DB7, pass (1UL &lt;&lt; 32) | 0x04C11DB7 = 0x104C11DB7.
        /// </param>
        /// <param name="degree">The degree of the polynomial (e.g. 32 for CRC-32).</param>
        /// <param name="power">The exponent N in x^N.</param>
        /// <returns>The remainder x^power mod poly, which has at most <paramref name="degree"/> bits.</returns>
        internal static ulong ModPow(ulong poly, int degree, int power)
        {
            // Compute x^power mod poly using repeated squaring in GF(2).
            ulong result = 1; // x^0
            ulong base_ = 2; // x^1

            int p = power;
            while (p > 0)
            {
                if ((p & 1) != 0)
                {
                    result = Gf2Multiply(result, base_, poly, degree);
                }
                base_ = Gf2Multiply(base_, base_, poly, degree);
                p >>= 1;
            }

            return result;
        }

        /// <summary>
        /// Computes x^(2*degree) / poly in GF(2), returning the quotient (Barrett constant mu).
        /// </summary>
        internal static ulong BarrettQuotient(ulong poly, int degree)
        {
            UInt128 dividend = (UInt128)1 << (2 * degree);
            UInt128 polyWide = poly;
            ulong quotient = 0;

            while (true)
            {
                int d = Log2(dividend);
                if (d < degree)
                    break;
                int shift = d - degree;
                dividend ^= polyWide << shift;
                quotient ^= 1UL << shift;
            }

            return quotient;
        }

        /// <summary>
        /// Reverses the bits of a value within the specified width.
        /// </summary>
        internal static ulong ReverseBits(ulong value, int width)
        {
            ulong result = 0;
            for (int i = 0; i < width; i++)
            {
                if ((value & (1UL << i)) != 0)
                {
                    result |= 1UL << (width - 1 - i);
                }
            }

            return result;
        }

        /// <summary>
        /// Computes the folding constants for a reflected CRC-32 polynomial.
        /// </summary>
        /// <param name="polynomial">The CRC polynomial in normal (unreflected) form, without the leading x^32 term.</param>
        /// <param name="k1k2">The constants for 4-block (64-byte) folding.</param>
        /// <param name="k3k4">The constants for 1-block (16-byte) folding.</param>
        /// <param name="k5">The constant for 128→64 bit folding.</param>
        /// <param name="muPoly">The Barrett reduction constants (mu and reflected polynomial).</param>
        /// <param name="k4Scalar">The k4 constant for 128→64 fold first step.</param>
        internal static void ComputeReflectedCrc32Constants(
            uint polynomial,
            out Vector128<ulong> k1k2,
            out Vector128<ulong> k3k4,
            out ulong k5,
            out ulong k4Scalar,
            out Vector128<ulong> muPoly)
        {
            const int Degree = 32;
            ulong poly = (1UL << Degree) | polynomial;

            // Folding constants: reverse_bits_{deg+1}(x^N mod P_normal)
            ulong k1 = ReverseBits(ModPow(poly, Degree, 4 * 128 + Degree), Degree + 1);
            ulong k2 = ReverseBits(ModPow(poly, Degree, 4 * 128 - Degree), Degree + 1);
            ulong k3 = ReverseBits(ModPow(poly, Degree, 128 + Degree), Degree + 1);
            ulong k4 = ReverseBits(ModPow(poly, Degree, 128 - Degree), Degree + 1);
            ulong k5Val = ReverseBits(ModPow(poly, Degree, 2 * Degree), Degree + 1);

            // Barrett constants
            ulong mu = ReverseBits(BarrettQuotient(poly, Degree), Degree + 1);
            ulong polyReflected = ReverseBits(poly, Degree + 1);

            k1k2 = Vector128.Create(k1, k2);
            k3k4 = Vector128.Create(k3, k4);
            k5 = k5Val;
            k4Scalar = k4;
            muPoly = Vector128.Create(polyReflected, mu);
        }

        /// <summary>
        /// Multiplies two values in GF(2) and reduces mod poly.
        /// </summary>
        private static ulong Gf2Multiply(ulong a, ulong b, ulong poly, int degree)
        {
            // Carryless multiply a * b, then reduce mod poly.
            // Both a and b have at most 'degree' bits.
            // The product has at most 2*degree bits, which fits in UInt128.

            UInt128 product = 0;
            UInt128 bWide = b;

            while (a != 0)
            {
                if ((a & 1) != 0)
                {
                    product ^= bWide;
                }
                bWide <<= 1;
                a >>= 1;
            }

            // Reduce mod poly
            UInt128 polyWide = poly;
            while (true)
            {
                int d = Log2(product);
                if (d < degree)
                    break;
                int shift = d - degree;
                product ^= polyWide << shift;
            }

            return (ulong)product;
        }

        private static int Log2(UInt128 value)
        {
            if (value == 0)
                return -1;

            ulong hi = (ulong)(value >> 64);
            if (hi != 0)
            {
                return 64 + 63 - System.Numerics.BitOperations.LeadingZeroCount(hi);
            }

            ulong lo = (ulong)value;
            return 63 - System.Numerics.BitOperations.LeadingZeroCount(lo);
        }
    }
}
#endif
