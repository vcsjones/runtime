// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers.Text;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace System.Security.Cryptography
{
    public static partial class PemEncoding
    {
        private static ReadOnlySpan<byte> s_preEBPrefix => "-----BEGIN "u8;
        private static ReadOnlySpan<byte> s_postEBPrefix => "-----END "u8;
        private static ReadOnlySpan<byte> s_ending => "-----"u8;

        /// <summary>
        /// Finds the first PEM-encoded data.
        /// </summary>
        /// <param name="pemData">
        /// The text containing the PEM-encoded data.
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="pemData"/> does not contain a well-formed PEM-encoded value.
        /// </exception>
        /// <returns>
        /// A value that specifies the location, label, and data location of
        /// the encoded data.
        /// </returns>
        /// <remarks>
        /// IETF RFC 7468 permits different decoding rules. This method
        /// always uses lax rules.
        /// </remarks>
        public static PemFields Find(ReadOnlySpan<byte> pemData)
        {
            if (!TryFind(pemData, out PemFields fields))
            {
                throw new ArgumentException(SR.Argument_PemEncoding_NoPemFound, nameof(pemData));
            }

            return fields;
        }

        /// <summary>
        /// Attempts to find the first PEM-encoded data.
        /// </summary>
        /// <param name="pemData">
        /// The text containing the PEM-encoded data.
        /// </param>
        /// <param name="fields">
        /// When this method returns, contains a value
        /// that specifies the location, label, and data location of the encoded data;
        /// or that specifies those locations as empty if no PEM-encoded data is found.
        /// This parameter is treated as uninitialized.
        /// </param>
        /// <returns>
        /// <c>true</c> if PEM-encoded data was found; otherwise <c>false</c>.
        /// </returns>
        /// <remarks>
        /// IETF RFC 7468 permits different decoding rules. This method
        /// always uses lax rules.
        /// </remarks>
        public static bool TryFind(ReadOnlySpan<byte> pemData, out PemFields fields)
        {
            // Check for the minimum possible encoded length of a PEM structure
            // and exit early if there is no way the input could contain a well-formed
            // PEM.
            if (pemData.Length < s_preEBPrefix.Length + s_ending.Length * 2 + s_postEBPrefix.Length)
            {
                fields = default;
                return false;
            }

            const int PostebStackBufferSize = 256;
            Span<byte> postebStackBuffer = stackalloc byte[PostebStackBufferSize];
            int areaOffset = 0;
            int preebIndex;
            while ((preebIndex = pemData.IndexOfByOffset(s_preEBPrefix, areaOffset)) >= 0)
            {
                int labelStartIndex = preebIndex + s_preEBPrefix.Length;

                // If there are any previous characters, the one prior to the PreEB
                // must be a white space character.
                if (preebIndex > 0 && !IsWhiteSpaceCharacter(pemData[preebIndex - 1]))
                {
                    areaOffset = labelStartIndex;
                    continue;
                }

                int preebEndIndex = pemData.IndexOfByOffset(s_ending, labelStartIndex);

                // There is no ending sequence, -----, in the remainder of
                // the document. Therefore, there can never be a complete PreEB
                // and we can exit.
                if (preebEndIndex < 0)
                {
                    fields = default;
                    return false;
                }

                Range labelRange = labelStartIndex..preebEndIndex;
                ReadOnlySpan<byte> label = pemData[labelRange];

                // There could be a preeb that is valid after this one if it has an invalid
                // label, so move from there.
                if (!IsValidLabel(label))
                {
                    goto NextAfterLabel;
                }

                int contentStartIndex = preebEndIndex + s_ending.Length;
                int postebLength = s_postEBPrefix.Length + label.Length + s_ending.Length;

                Span<byte> postebBuffer = postebLength > PostebStackBufferSize
                    ? new byte[postebLength]
                    : postebStackBuffer;
                ReadOnlySpan<byte> posteb = WritePostEB(label, postebBuffer);
                int postebStartIndex = pemData.IndexOfByOffset(posteb, contentStartIndex);

                if (postebStartIndex < 0)
                {
                    goto NextAfterLabel;
                }

                int pemEndIndex = postebStartIndex + postebLength;

                // The PostEB must either end at the end of the string, or
                // have at least one white space character after it.
                if (pemEndIndex < pemData.Length - 1 &&
                    !IsWhiteSpaceCharacter(pemData[pemEndIndex]))
                {
                    goto NextAfterLabel;
                }

                Range contentRange = contentStartIndex..postebStartIndex;

                if (!TryCountBase64(pemData[contentRange], out int base64start, out int base64end, out int decodedSize))
                {
                    goto NextAfterLabel;
                }

                Range pemRange = preebIndex..pemEndIndex;
                Range base64range = (contentStartIndex + base64start)..(contentStartIndex + base64end);
                fields = new PemFields(labelRange, base64range, pemRange, decodedSize);
                return true;

            NextAfterLabel:
                if (preebEndIndex <= areaOffset)
                {
                    // We somehow ended up in a situation where we will advance
                    // backward or not at all, which means we'll probably end up here again,
                    // advancing backward, in a loop. To avoid getting stuck,
                    // detect this situation and return.
                    fields = default;
                    return false;
                }
                areaOffset = preebEndIndex;
            }

            fields = default;
            return false;

            static ReadOnlySpan<byte> WritePostEB(ReadOnlySpan<byte> label, Span<byte> destination)
            {
                int size = s_postEBPrefix.Length + label.Length + s_ending.Length;
                Debug.Assert(destination.Length >= size);
                s_postEBPrefix.CopyTo(destination);
                label.CopyTo(destination.Slice(s_postEBPrefix.Length));
                s_ending.CopyTo(destination.Slice(s_postEBPrefix.Length + label.Length));
                return destination.Slice(0, size);
            }
        }

        private static int IndexOfByOffset(this ReadOnlySpan<byte> str, ReadOnlySpan<byte> value, int startPosition)
        {
            Debug.Assert(startPosition <= str.Length);
            int index = str.Slice(startPosition).IndexOf(value);
            return index == -1 ? -1 : index + startPosition;
        }

        private static bool IsValidLabel(ReadOnlySpan<byte> data)
        {
            static bool IsLabelChar(byte c) => (c - 0x21u) <= 0x5du && c != (byte)'-';

            // Empty labels are permitted per RFC 7468.
            if (data.IsEmpty)
                return true;

            // The first character must be a labelchar, so initialize to false
            bool previousIsLabelChar = false;

            for (int index = 0; index < data.Length; index++)
            {
                byte c = data[index];

                if (IsLabelChar(c))
                {
                    previousIsLabelChar = true;
                    continue;
                }

                bool isSpaceOrHyphen = c is (byte)' ' or (byte)'-';

                // IETF RFC 7468 states that every character in a label must
                // be a labelchar, and each labelchar may have zero or one
                // preceding space or hyphen, except the first labelchar.
                // If this character is not a space or hyphen, then this characer
                // is invalid.
                // If it is a space or hyphen, and the previous character was
                // also not a labelchar (another hyphen or space), then we have
                // two consecutive spaces or hyphens which is invalid.
                if (!isSpaceOrHyphen || !previousIsLabelChar)
                {
                    return false;
                }

                previousIsLabelChar = false;
            }

            // The last character must also be a labelchar. It cannot be a
            // hyphen or space since these are only allowed to precede
            // a labelchar.
            return previousIsLabelChar;
        }

        private static bool TryCountBase64(
            ReadOnlySpan<byte> str,
            out int base64Start,
            out int base64End,
            out int base64DecodedSize)
        {
            // Trim starting and ending allowed white space characters
            int start = 0;
            int end = str.Length - 1;
            for (; start < str.Length && IsWhiteSpaceCharacter(str[start]); start++);
            for (; end > start && IsWhiteSpaceCharacter(str[end]); end--);

            // Validate that the remaining characters are valid base-64 encoded data.
            if (Base64.IsValid(str.Slice(start, end + 1 - start), out base64DecodedSize))
            {
                base64Start = start;
                base64End = end + 1;
                return true;
            }

            base64Start = 0;
            base64End = 0;
            return false;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool IsBase64Character(byte ch)
        {
            return char.IsAsciiLetterOrDigit((char)ch) || ch is (byte)'+' or (byte)'/';
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool IsWhiteSpaceCharacter(byte ch)
        {
            // Match white space characters from Convert.Base64
            return ch is (byte)' ' or (byte)'\t' or (byte)'\n' or (byte)'\r';
        }

        /// <summary>
        /// Tries to write the provided data and label as PEM-encoded data into
        /// a provided buffer.
        /// </summary>
        /// <param name="label">
        /// The label to write.
        /// </param>
        /// <param name="data">
        /// The data to write.
        /// </param>
        /// <param name="destination">
        /// The buffer to receive the PEM-encoded text.
        /// </param>
        /// <param name="charsWritten">
        /// When this method returns, this parameter contains the number of characters
        /// written to <paramref name="destination"/>. This parameter is treated
        /// as uninitialized.
        /// </param>
        /// <returns>
        /// <c>true</c> if <paramref name="destination"/> is large enough to contain
        /// the PEM-encoded text, otherwise <c>false</c>.
        /// </returns>
        /// <remarks>
        /// This method always wraps the base-64 encoded text to 64 characters, per the
        /// recommended wrapping of IETF RFC 7468. Unix-style line endings are used for line breaks.
        /// </remarks>
        /// <exception cref="ArgumentOutOfRangeException">
        ///   <paramref name="label"/> exceeds the maximum possible label length.
        ///   <para>
        ///       -or-
        ///   </para>
        ///   <paramref name="data"/> exceeds the maximum possible encoded data length.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// The resulting PEM-encoded text is larger than <see cref="int.MaxValue"/>.
        ///   <para>
        ///       - or -
        ///   </para>
        /// <paramref name="label"/> contains invalid characters.
        /// </exception>
        public static bool TryWrite(ReadOnlySpan<byte> label, ReadOnlySpan<byte> data, Span<byte> destination, out int charsWritten)
        {
            if (!IsValidLabel(label))
                throw new ArgumentException(SR.Argument_PemEncoding_InvalidLabel, nameof(label));

            int encodedSize = GetEncodedSize(label.Length, data.Length);

            if (destination.Length < encodedSize)
            {
                charsWritten = 0;
                return false;
            }

            charsWritten = WriteCore(label, data, destination);
            Debug.Assert(encodedSize == charsWritten);
            return true;
        }

        private static int WriteCore(ReadOnlySpan<byte> label, ReadOnlySpan<byte> data, Span<byte> destination)
        {
            static int Write(ReadOnlySpan<byte> str, Span<byte> dest, int offset)
            {
                str.CopyTo(dest.Slice(offset));
                return str.Length;
            }

            static int WriteBase64(ReadOnlySpan<byte> bytes, Span<byte> dest, int offset)
            {
                Buffers.OperationStatus status = Base64.EncodeToUtf8(bytes, dest.Slice(offset), out _, out int base64Written);

                if (status != Buffers.OperationStatus.Done)
                {
                    Debug.Fail("Convert.TryToBase64Chars failed with a pre-sized buffer");
                    throw new ArgumentException(null, nameof(destination));
                }

                return base64Written;
            }

            ReadOnlySpan<byte> NewLine = "\n"u8;
            const int BytesPerLine = 48;

            int charsWritten = 0;
            charsWritten += Write(s_preEBPrefix, destination, charsWritten);
            charsWritten += Write(label, destination, charsWritten);
            charsWritten += Write(s_ending, destination, charsWritten);
            charsWritten += Write(NewLine, destination, charsWritten);

            ReadOnlySpan<byte> remainingData = data;
            while (remainingData.Length >= BytesPerLine)
            {
                charsWritten += WriteBase64(remainingData.Slice(0, BytesPerLine), destination, charsWritten);
                charsWritten += Write(NewLine, destination, charsWritten);
                remainingData = remainingData.Slice(BytesPerLine);
            }

            Debug.Assert(remainingData.Length < BytesPerLine);

            if (remainingData.Length > 0)
            {
                charsWritten += WriteBase64(remainingData, destination, charsWritten);
                charsWritten += Write(NewLine, destination, charsWritten);
            }

            charsWritten += Write(s_postEBPrefix, destination, charsWritten);
            charsWritten += Write(label, destination, charsWritten);
            charsWritten += Write(s_ending, destination, charsWritten);

            return charsWritten;
        }

        /// <summary>
        /// Creates an encoded PEM with the given label and data.
        /// </summary>
        /// <param name="label">
        /// The label to encode.
        /// </param>
        /// <param name="data">
        /// The data to encode.
        /// </param>
        /// <returns>
        /// A character array of the encoded PEM.
        /// </returns>
        /// <remarks>
        /// This method always wraps the base-64 encoded text to 64 characters, per the
        /// recommended wrapping of RFC-7468. Unix-style line endings are used for line breaks.
        /// </remarks>
        /// <exception cref="ArgumentOutOfRangeException">
        ///   <paramref name="label"/> exceeds the maximum possible label length.
        ///   <para>
        ///       -or-
        ///   </para>
        ///   <paramref name="data"/> exceeds the maximum possible encoded data length.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// The resulting PEM-encoded text is larger than <see cref="int.MaxValue"/>.
        ///   <para>
        ///       - or -
        ///   </para>
        /// <paramref name="label"/> contains invalid characters.
        /// </exception>
        public static byte[] Write(ReadOnlySpan<byte> label, ReadOnlySpan<byte> data)
        {
            if (!IsValidLabel(label))
                throw new ArgumentException(SR.Argument_PemEncoding_InvalidLabel, nameof(label));

            int encodedSize = GetEncodedSize(label.Length, data.Length);
            byte[] buffer = new byte[encodedSize];

            int charsWritten = WriteCore(label, data, buffer);
            Debug.Assert(charsWritten == encodedSize);
            return buffer;
        }
    }
}
