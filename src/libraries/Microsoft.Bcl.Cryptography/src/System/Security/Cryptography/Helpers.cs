// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Security.Cryptography;

// TODO: This should be able to be deleted when the old counting code is removed.
namespace System.Security.Cryptography
{
    namespace X509Certificates
    {
        internal sealed class X509IterationCountExceededException : Exception
        {
        }
    }

    internal static class KdfWorkLimiter
    {
        internal static void RecordIterations(long workCount)
        {
            Debug.Assert(workCount >= 0);
        }
    }
}

namespace Internal.Cryptography
{
    internal static partial class Helpers
    {
        internal static ReadOnlyMemory<byte> DecodeOctetStringAsMemory(ReadOnlyMemory<byte> encodedOctetString)
        {
            try
            {
                ReadOnlySpan<byte> input = encodedOctetString.Span;

                if (AsnDecoder.TryReadPrimitiveOctetString(
                    input,
                    AsnEncodingRules.BER,
                    out ReadOnlySpan<byte> primitive,
                    out int consumed))
                {
                    if (consumed != input.Length)
                    {
                        throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                    }

                    if (input.Overlaps(primitive, out int offset))
                    {
                        return encodedOctetString.Slice(offset, primitive.Length);
                    }

                    Debug.Fail("input.Overlaps(primitive) failed after TryReadPrimitiveOctetString succeeded");
                }

                byte[] ret = AsnDecoder.ReadOctetString(input, AsnEncodingRules.BER, out consumed);

                if (consumed != input.Length)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                return ret;
            }
            catch (AsnContentException e)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding, e);
            }
        }
    }
}
