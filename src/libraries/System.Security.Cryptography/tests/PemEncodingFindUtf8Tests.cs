// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Text;
using Xunit;

namespace System.Security.Cryptography.Tests
{
    public abstract class PemEncodingFindUtf8Tests
    {
        [Fact]
        public void Find_Success_Simple()
        {
            ReadOnlySpan<byte> content = "-----BEGIN TEST-----\nZm9v\n-----END TEST-----"u8;
            PemFields fields = AssertPemFound(content,
                expectedLocation: 0..44,
                expectedBase64: 21..25,
                expectedLabel: 11..15);
            AssertExtensions.SequenceEqual("TEST"u8, content[fields.Label]);
            AssertExtensions.SequenceEqual(content, content[fields.Location]);
            AssertExtensions.SequenceEqual("Zm9v"u8, content[fields.Base64Data]);
            Assert.Equal(3, fields.DecodedDataLength);
        }

        [Fact]
        public void Find_Success_IncompletePreebPrefixed()
        {
            ReadOnlySpan<byte> content = "-----BEGIN FAIL -----BEGIN TEST-----\nZm9v\n-----END TEST-----"u8;
            AssertPemFound(content,
                expectedLocation: 16..60,
                expectedBase64: 37..41,
                expectedLabel: 27..31);
        }

        [Fact]
        public void Find_Success_CompletePreebPrefixedDifferentLabel()
        {
            ReadOnlySpan<byte> content = "-----BEGIN FAIL----- -----BEGIN TEST-----\nZm9v\n-----END TEST-----"u8;
            PemFields fields = AssertPemFound(content,
                expectedLocation: 21..65,
                expectedBase64: 42..46,
                expectedLabel: 32..36);

            AssertExtensions.SequenceEqual("TEST"u8, content[fields.Label]);
        }

        [Fact]
        public void Find_Success_CompletePreebPrefixedSameLabel()
        {
            ReadOnlySpan<byte> content = "-----BEGIN TEST----- -----BEGIN TEST-----\nZm9v\n-----END TEST-----"u8;
            PemFields fields = AssertPemFound(content,
                expectedLocation: 21..65,
                expectedBase64: 42..46,
                expectedLabel: 32..36);

            AssertExtensions.SequenceEqual("TEST"u8, content[fields.Label]);
        }

        [Fact]
        public void Find_Success_PreebEndingOverlap()
        {
            ReadOnlySpan<byte> content = "-----BEGIN TEST -----BEGIN TEST-----\nZm9v\n-----END TEST-----"u8;
            PemFields fields = AssertPemFound(content,
                expectedLocation: 16..60,
                expectedBase64: 37..41,
                expectedLabel: 27..31);

            AssertExtensions.SequenceEqual("TEST"u8, content[fields.Label]);
            Assert.Equal(3, fields.DecodedDataLength);
        }

        [Fact]
        public void Find_Success_LargeLabel()
        {
            string label = new string('A', 275);
            string utf16Content = $"-----BEGIN {label}-----\nZm9v\n-----END {label}-----";
            byte[] content = Encoding.UTF8.GetBytes(utf16Content);
            PemFields fields = AssertPemFound(content,
                expectedLocation: 0..586,
                expectedBase64: 292..296,
                expectedLabel: 11..286);

            AssertExtensions.SequenceEqual(Encoding.UTF8.GetBytes(label), content[fields.Label]);
        }

        [Fact]
        public void Find_Success_Minimum()
        {
            ReadOnlySpan<byte> content = "-----BEGIN ----------END -----"u8;
            PemFields fields = AssertPemFound(content,
                expectedLocation: 0..30,
                expectedBase64: 16..16,
                expectedLabel: 11..11);
            Assert.Equal(0, fields.DecodedDataLength);
        }

        [Fact]
        public void Find_Success_PrecedingContentAndWhitespaceBeforePreeb()
        {
            ReadOnlySpan<byte> content = "boop   -----BEGIN TEST-----\nZm9v\n-----END TEST-----"u8;
            AssertPemFound(content,
                expectedLocation: 7..51,
                expectedBase64: 28..32,
                expectedLabel: 18..22);
        }

        [Fact]
        public void Find_Success_TrailingWhitespaceAfterPosteb()
        {
            ReadOnlySpan<byte> content = "-----BEGIN TEST-----\nZm9v\n-----END TEST-----    "u8;
            AssertPemFound(content,
                expectedLocation: 0..44,
                expectedBase64: 21..25,
                expectedLabel: 11..15);
        }

        [Fact]
        public void Find_Success_EmptyLabel()
        {
            ReadOnlySpan<byte> content = "-----BEGIN -----\nZm9v\n-----END -----"u8;
            AssertPemFound(content,
                expectedLocation: 0..36,
                expectedBase64: 17..21,
                expectedLabel: 11..11);
        }

        [Fact]
        public void Find_Success_EmptyContent_OneLine()
        {
            ReadOnlySpan<byte> content = "-----BEGIN EMPTY----------END EMPTY-----"u8;
            PemFields fields = AssertPemFound(content,
                expectedLocation: 0..40,
                expectedBase64: 21..21,
                expectedLabel: 11..16);
            Assert.Equal(0, fields.DecodedDataLength);
        }

        [Fact]
        public void Find_Success_EmptyContent_ManyLinesOfWhitespace()
        {
            ReadOnlySpan<byte> content = "-----BEGIN EMPTY-----\n\t\n\t\n\t  \n-----END EMPTY-----"u8;
            PemFields fields = AssertPemFound(content,
                expectedLocation: 0..49,
                expectedBase64: 30..30,
                expectedLabel: 11..16);
            Assert.Equal(0, fields.DecodedDataLength);
        }

        [Theory]
        [InlineData("CERTIFICATE")]
        [InlineData("X509 CRL")]
        [InlineData("PKCS7")]
        [InlineData("PRIVATE KEY")]
        [InlineData("RSA PRIVATE KEY")]
        public void Find_Success_CommonLabels(string labelUtf16)
        {
            byte[] label = Encoding.UTF8.GetBytes(labelUtf16);
            byte[] content = Combine("-----BEGIN "u8, label, "-----\nZm9v\n-----END "u8, label, "-----"u8);
            PemFields fields = FindPem(content);
            AssertExtensions.SequenceEqual(label, content[fields.Label]);
        }

        [Theory]
        [InlineData("H E L L O")]
        [InlineData("H-E-L-L-O")]
        [InlineData("HEL-LO")]
        public void Find_Success_LabelsWithHyphenSpace(string labelUtf16)
        {
            byte[] label = Encoding.UTF8.GetBytes(labelUtf16);
            byte[] content = Combine("-----BEGIN "u8, label, "-----\nZm9v\n-----END "u8, label, "-----"u8);
            PemFields fields = FindPem(content);
            AssertExtensions.SequenceEqual(label, content[fields.Label]);
        }

        [Fact]
        public void Find_Success_SingleLetterLabel()
        {
            ReadOnlySpan<byte> content = "-----BEGIN H-----\nZm9v\n-----END H-----"u8;
            AssertPemFound(content,
                expectedLocation: 0..38,
                expectedBase64: 18..22,
                expectedLabel: 11..12);
        }

        [Fact]
        public void Find_Success_LabelCharacterBoundaries()
        {
            ReadOnlySpan<byte> content = "-----BEGIN !PANIC~~~-----\nAHHH\n-----END !PANIC~~~-----"u8;
            AssertPemFound(content,
                expectedLocation: 0..54,
                expectedBase64: 26..30,
                expectedLabel: 11..20);
        }

        [Theory]
        [InlineData((byte)' ')]
        [InlineData((byte)'\n')]
        [InlineData((byte)'\r')]
        [InlineData((byte)'\t')]
        public void Find_Success_WhiteSpaceBeforePreebSeparatesFromPriorContent(byte whiteSpaceChar)
        {
            ReadOnlySpan<byte> whiteSpace = new ReadOnlySpan<byte>(whiteSpaceChar);
            byte[] content = Combine("blah"u8, whiteSpace, "-----BEGIN TEST-----\nZn9v\n-----END TEST-----"u8);
            AssertPemFound(content,
                expectedLocation: 5..49,
                expectedBase64: 26..30,
                expectedLabel: 16..20);
        }

        [Theory]
        [InlineData((byte)' ')]
        [InlineData((byte)'\n')]
        [InlineData((byte)'\r')]
        [InlineData((byte)'\t')]
        public void Find_Success_WhiteSpaceAfterPpostebSeparatesFromSubsequentContent(byte whiteSpaceChar)
        {
            ReadOnlySpan<byte> whiteSpace = new ReadOnlySpan<byte>(whiteSpaceChar);
            byte[] content = Combine("-----BEGIN TEST-----\nZn9v\n-----END TEST-----"u8, whiteSpace, "blah"u8);
            AssertPemFound(content,
                expectedLocation: 0..44,
                expectedBase64: 21..25,
                expectedLabel: 11..15);
        }

        [Fact]
        public void Find_Success_Base64SurroundingWhiteSpaceStripped()
        {
            ReadOnlySpan<byte> content = "-----BEGIN A-----\r\n Zm9v\n\r \t-----END A-----"u8;
            AssertPemFound(content,
                expectedLocation: 0..43,
                expectedBase64: 20..24,
                expectedLabel: 11..12);
        }

        [Fact]
        public void Find_Success_FindsPemAfterPemWithInvalidBase64()
        {
            ReadOnlySpan<byte> content = @"
-----BEGIN TEST-----
$$$$
-----END TEST-----
-----BEGIN TEST2-----
Zm9v
-----END TEST2-----"u8;
            PemFields fields = FindPem(content);
            AssertExtensions.SequenceEqual("TEST2"u8, content[fields.Label]);
            AssertExtensions.SequenceEqual("Zm9v"u8, content[fields.Base64Data]);
        }

        [Fact]
        public void Find_Success_FindsPemAfterPemWithInvalidLabel()
        {
            ReadOnlySpan<byte> content = @"
-----BEGIN ------
YmFy
-----END ------
-----BEGIN TEST2-----
Zm9v
-----END TEST2-----"u8;

            PemFields fields = FindPem(content);
            AssertExtensions.SequenceEqual("TEST2"u8, content[fields.Label]);
            AssertExtensions.SequenceEqual("Zm9v"u8, content[fields.Base64Data]);
        }

        [Fact]
        public void TryFind_Success_AfterSuccessiveInvalidBase64()
        {
            StringBuilder builder = new StringBuilder();

            for (int i = 0; i < 100; i++)
            {
                builder.Append($"-----BEGIN CERTIFICATE-----\n${i:000}\n-----END CERTIFICATE-----\n");
            }

            builder.Append($"-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----");
            string utf16 = builder.ToString();
            byte[] pem = Encoding.UTF8.GetBytes(utf16);

            AssertPemFound(pem,
                expectedLocation: 5900..5958,
                expectedBase64: 5928..5932,
                expectedLabel: 5911..5922);
        }

        [Fact]
        public void Find_Fail_Empty()
        {
            AssertNoPemFound(ReadOnlySpan<byte>.Empty);
        }

        [Fact]
        public void Find_Fail_InvalidBase64_MultipleInvalid_WithSurroundingText()
        {
            ReadOnlySpan<byte> content = @"
CN=Intermediate1
-----BEGIN CERTIFICATE-----
MII
-----END CERTIFICATE-----
CN=Intermediate2
-----BEGIN CERTIFICATE-----
MII
-----END CERTIFICATE-----
"u8;
            AssertNoPemFound(content);
        }

        [Fact]
        public void Find_Fail_PostEbBeforePreEb()
        {
            ReadOnlySpan<byte> content = "-----END TEST-----\n-----BEGIN TEST-----\nZm9v"u8;
            AssertNoPemFound(content);
        }

        [Theory]
        [InlineData("\tOOPS")]
        [InlineData(" OOPS")]
        [InlineData(" ")]
        [InlineData("-")]
        [InlineData("-OOPS")]
        [InlineData("te\x7fst")]
        [InlineData("te\x19st")]
        [InlineData("te  st")] //two spaces
        [InlineData("te- st")]
        [InlineData("test ")] //last is space, must be labelchar
        [InlineData("test-")] //last is hyphen, must be labelchar
        public void Find_Fail_InvalidLabel(string labelUtf16)
        {
            byte[] label = Encoding.UTF8.GetBytes(labelUtf16);
            byte[] content = Combine("-----BEGIN "u8, label, "-----\nZm9v\n-----END "u8, label, "-----"u8);
            AssertNoPemFound(content);
        }

        [Fact]
        public void Find_Fail_InvalidBase64()
        {
            ReadOnlySpan<byte> content = "-----BEGIN TEST-----\n$$$$\n-----END TEST-----"u8;
            AssertNoPemFound(content);
        }

        [Fact]
        public void Find_Fail_PrecedingLinesAndSignificantCharsBeforePreeb()
        {
            ReadOnlySpan<byte> content = "boop\nbeep-----BEGIN TEST-----\nZm9v\n-----END TEST-----"u8;
            AssertNoPemFound(content);
        }


        [Theory]
        [InlineData("\u200A")] // hair space
        [InlineData("\v")]
        [InlineData("\f")]
        public void Find_Fail_NotPermittedWhiteSpaceSeparatorsForPreeb(string whiteSpaceUtf16)
        {
            byte[] whiteSpace = Encoding.UTF8.GetBytes(whiteSpaceUtf16);
            byte[] content = Combine("boop"u8, whiteSpace, "-----BEGIN TEST-----\nZm9v\n-----END TEST-----"u8);
            AssertNoPemFound(content);
        }

        [Theory]
        [InlineData("\u200A")] // hair space
        [InlineData("\v")]
        [InlineData("\f")]
        public void Find_Fail_NotPermittedWhiteSpaceSeparatorsForPosteb(string whiteSpaceUtf16)
        {
            byte[] whiteSpace = Encoding.UTF8.GetBytes(whiteSpaceUtf16);
            byte[] content = Combine("-----BEGIN TEST-----\nZm9v\n-----END TEST-----"u8, whiteSpace, "boop"u8);
            AssertNoPemFound(content);
        }

        [Fact]
        public void Find_Fail_ContentOnPostEbLine()
        {
            ReadOnlySpan<byte> content = "-----BEGIN TEST-----\nZm9v\n-----END TEST-----boop"u8;
            AssertNoPemFound(content);
        }

        [Fact]
        public void Find_Fail_MismatchedLabels()
        {
            ReadOnlySpan<byte> content = "-----BEGIN TEST-----\nZm9v\n-----END FAIL-----"u8;
            AssertNoPemFound(content);
        }

        [Fact]
        public void Find_Fail_NoPostEncapBoundary()
        {
            ReadOnlySpan<byte> content = "-----BEGIN TEST-----\nZm9v\n"u8;
            AssertNoPemFound(content);
        }

        [Fact]
        public void Find_Fail_IncompletePostEncapBoundary()
        {
            ReadOnlySpan<byte> content = "-----BEGIN TEST-----\nZm9v\n-----END TEST"u8;
            AssertNoPemFound(content);
        }

        [Fact]
        public void Find_Fail_InvalidBase64_Size()
        {
            ReadOnlySpan<byte> content = "-----BEGIN TEST-----\nZ\n-----END TEST-----"u8;
            AssertNoPemFound(content);
        }

        [Fact]
        public void Find_Fail_InvalidBase64_ExtraPadding()
        {
            ReadOnlySpan<byte> content = "-----BEGIN TEST-----\nZm9v====\n-----END TEST-----"u8;
            AssertNoPemFound(content);
        }

        [Fact]
        public void Find_Fail_InvalidBase64_MissingPadding()
        {
            ReadOnlySpan<byte> content = "-----BEGIN TEST-----\nZm8\n-----END TEST-----"u8;
            AssertNoPemFound(content);
        }

        private PemFields AssertPemFound(
            ReadOnlySpan<byte> input,
            Range expectedLocation,
            Range expectedBase64,
            Range expectedLabel)
        {
            PemFields fields = FindPem(input);
            Assert.Equal(expectedBase64, fields.Base64Data);
            Assert.Equal(expectedLocation, fields.Location);
            Assert.Equal(expectedLabel, fields.Label);

            return fields;
        }

        protected abstract void AssertNoPemFound(ReadOnlySpan<byte> input);

        protected abstract PemFields FindPem(ReadOnlySpan<byte> input);

        private static byte[] Combine(ReadOnlySpan<byte> input1, ReadOnlySpan<byte> input2)
        {
            int size = checked(input1.Length + input2.Length);
            byte[] ret = new byte[size];
            Span<byte> buffer = ret;
            input1.CopyTo(buffer);
            buffer = buffer.Slice(input1.Length);
            input2.CopyTo(buffer);

            return ret;
        }

        private static byte[] Combine(ReadOnlySpan<byte> input1, ReadOnlySpan<byte> input2, ReadOnlySpan<byte> input3)
        {
            int size = checked(input1.Length + input2.Length + input3.Length);
            byte[] ret = new byte[size];
            Span<byte> buffer = ret;
            input1.CopyTo(buffer);
            buffer = buffer.Slice(input1.Length);
            input2.CopyTo(buffer);
            buffer = buffer.Slice(input2.Length);
            input3.CopyTo(buffer);
            return ret;
        }

        private static byte[] Combine(ReadOnlySpan<byte> input1, ReadOnlySpan<byte> input2, ReadOnlySpan<byte> input3, ReadOnlySpan<byte> input4)
        {
            int size = checked(input1.Length + input2.Length + input3.Length + input4.Length);
            byte[] ret = new byte[size];
            Span<byte> buffer = ret;
            input1.CopyTo(buffer);
            buffer = buffer.Slice(input1.Length);
            input2.CopyTo(buffer);
            buffer = buffer.Slice(input2.Length);
            input3.CopyTo(buffer);
            buffer = buffer.Slice(input3.Length);
            input4.CopyTo(buffer);
            return ret;
        }

        private static byte[] Combine(ReadOnlySpan<byte> input1, ReadOnlySpan<byte> input2, ReadOnlySpan<byte> input3, ReadOnlySpan<byte> input4, ReadOnlySpan<byte> input5)
        {
            int size = checked(input1.Length + input2.Length + input3.Length + input4.Length + input5.Length);
            byte[] ret = new byte[size];
            Span<byte> buffer = ret;
            input1.CopyTo(buffer);
            buffer = buffer.Slice(input1.Length);
            input2.CopyTo(buffer);
            buffer = buffer.Slice(input2.Length);
            input3.CopyTo(buffer);
            buffer = buffer.Slice(input3.Length);
            input4.CopyTo(buffer);
            buffer = buffer.Slice(input4.Length);
            input5.CopyTo(buffer);
            return ret;
        }
    }

    public class PemEncodingFindUtf8ThrowingTests : PemEncodingFindUtf8Tests
    {
        protected override PemFields FindPem(ReadOnlySpan<byte> input) => PemEncoding.Find(input);

        protected override void AssertNoPemFound(ReadOnlySpan<byte> input)
        {
            AssertExtensions.Throws<ArgumentException, byte>("pemData", input, x => PemEncoding.Find(x));
        }
    }

    public class PemEncodingFindUtf8TryTests : PemEncodingFindUtf8Tests
    {
        protected override PemFields FindPem(ReadOnlySpan<byte> input)
        {
            bool found = PemEncoding.TryFind(input, out PemFields fields);
            Assert.True(found, "Did not find PEM.");
            return fields;
        }

        protected override void AssertNoPemFound(ReadOnlySpan<byte> input)
        {
            bool found = PemEncoding.TryFind(input, out _);
            Assert.False(found, "Found PEM when not expected");
        }
    }
}
