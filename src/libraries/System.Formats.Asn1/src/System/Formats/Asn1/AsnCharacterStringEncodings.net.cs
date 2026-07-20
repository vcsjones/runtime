// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Diagnostics;
using System.Text;

namespace System.Formats.Asn1
{
    internal sealed class IA5Encoding : SpanBasedEncoding
    {
        public override int GetMaxByteCount(int charCount)
        {
            return charCount;
        }

        public override int GetMaxCharCount(int byteCount)
        {
            return byteCount;
        }

        protected override int GetBytes(ReadOnlySpan<char> chars, Span<byte> bytes, bool write)
        {
            if (!write)
            {
                if (Ascii.IsValid(chars))
                {
                    return chars.Length;
                }

                for (int i = 0; i < chars.Length; i++)
                {
                    char c = chars[i];

                    if (!Ascii.IsValid(c))
                    {
                        ThrowEncoderFallback(c, i);
                    }
                }

                Debug.Fail("Ascii.IsValid returned inconsistent results");
                throw new InvalidOperationException();
            }

            OperationStatus status = Ascii.FromUtf16(chars, bytes, out int bytesWritten);

            if (status == OperationStatus.InvalidData)
            {
                ThrowEncoderFallback(chars[bytesWritten], bytesWritten);
            }

            if (status == OperationStatus.DestinationTooSmall)
            {
                char c = chars[bytesWritten];

                // Preserve the scalar implementation's validation-before-write ordering.
                if (!Ascii.IsValid(c))
                {
                    ThrowEncoderFallback(c, bytesWritten);
                }

                bytes[bytesWritten] = (byte)c;
            }

            Debug.Assert(status == OperationStatus.Done);
            return bytesWritten;
        }

        protected override int GetChars(ReadOnlySpan<byte> bytes, Span<char> chars, bool write)
        {
            if (!write)
            {
                if (Ascii.IsValid(bytes))
                {
                    return bytes.Length;
                }

                for (int i = 0; i < bytes.Length; i++)
                {
                    byte b = bytes[i];

                    if (!Ascii.IsValid(b))
                    {
                        ThrowDecoderFallback(b, i);
                    }
                }

                Debug.Fail("Ascii.IsValid returned inconsistent results");
                throw new InvalidOperationException();
            }

            OperationStatus status = Ascii.ToUtf16(bytes, chars, out int charsWritten);

            if (status == OperationStatus.InvalidData)
            {
                ThrowDecoderFallback(bytes[charsWritten], charsWritten);
            }

            if (status == OperationStatus.DestinationTooSmall)
            {
                byte b = bytes[charsWritten];

                // Preserve the scalar implementation's validation-before-write ordering.
                if (!Ascii.IsValid(b))
                {
                    ThrowDecoderFallback(b, charsWritten);
                }

                chars[charsWritten] = (char)b;
            }

            Debug.Assert(status == OperationStatus.Done);
            return charsWritten;
        }

        private void ThrowDecoderFallback(byte value, int index)
        {
            DecoderFallback.CreateFallbackBuffer().Fallback(new[] { value }, index);

            Debug.Fail("Fallback should have thrown");
            throw new InvalidOperationException();
        }

        private void ThrowEncoderFallback(char value, int index)
        {
            EncoderFallback.CreateFallbackBuffer().Fallback(value, index);

            Debug.Fail("Fallback should have thrown");
            throw new InvalidOperationException();
        }
    }
}
