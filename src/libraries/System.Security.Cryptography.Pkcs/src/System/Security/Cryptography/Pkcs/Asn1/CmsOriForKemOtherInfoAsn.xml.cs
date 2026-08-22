// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#pragma warning disable SA1028 // ignore whitespace warnings for generated code
using System;
using System.Formats.Asn1;
using System.Runtime.InteropServices;

namespace System.Security.Cryptography.Pkcs.Asn1
{
    [StructLayout(LayoutKind.Sequential)]
    internal ref partial struct ValueCmsOriForKemOtherInfoAsn
    {
        internal System.Security.Cryptography.Asn1.ValueAlgorithmIdentifierAsn Wrap;
        internal int KekLength;

        internal ReadOnlySpan<byte> Ukm
        {
            get;
            set
            {
                HasUkm = true;
                field = value;
            }
        }

        internal bool HasUkm { get; private set; }

        internal readonly void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }

        internal readonly void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);

            Wrap.Encode(writer);
            writer.WriteInteger(KekLength);

            if (HasUkm)
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
                writer.WriteOctetString(Ukm);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            }

            writer.PopSequence(tag);
        }

        internal static void Decode(ReadOnlySpan<byte> encoded, AsnEncodingRules ruleSet, out ValueCmsOriForKemOtherInfoAsn decoded)
        {
            Decode(Asn1Tag.Sequence, encoded, ruleSet, out decoded);
        }

        internal static void Decode(Asn1Tag expectedTag, ReadOnlySpan<byte> encoded, AsnEncodingRules ruleSet, out ValueCmsOriForKemOtherInfoAsn decoded)
        {
            try
            {
                ValueAsnReader reader = new ValueAsnReader(encoded, ruleSet);

                DecodeCore(ref reader, expectedTag, out decoded);
                reader.ThrowIfNotEmpty();
            }
            catch (AsnContentException e)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding, e);
            }
        }

        internal static void Decode(scoped ref ValueAsnReader reader, out ValueCmsOriForKemOtherInfoAsn decoded)
        {
            Decode(ref reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode(scoped ref ValueAsnReader reader, Asn1Tag expectedTag, out ValueCmsOriForKemOtherInfoAsn decoded)
        {
            try
            {
                DecodeCore(ref reader, expectedTag, out decoded);
            }
            catch (AsnContentException e)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding, e);
            }
        }

        private static void DecodeCore(scoped ref ValueAsnReader reader, Asn1Tag expectedTag, out ValueCmsOriForKemOtherInfoAsn decoded)
        {
            decoded = default;
            ValueAsnReader sequenceReader = reader.ReadSequence(expectedTag);
            ValueAsnReader explicitReader;
            ReadOnlySpan<byte> tmpSpan;

            System.Security.Cryptography.Asn1.ValueAlgorithmIdentifierAsn.Decode(ref sequenceReader, out decoded.Wrap);

            if (!sequenceReader.TryReadInt32(out decoded.KekLength))
            {
                sequenceReader.ThrowIfNotEmpty();
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

                if (explicitReader.TryReadPrimitiveOctetString(out tmpSpan))
                {
                    decoded.Ukm = tmpSpan;
                }
                else
                {
                    decoded.Ukm = explicitReader.ReadOctetString();
                }

                decoded.HasUkm = true;
                explicitReader.ThrowIfNotEmpty();
            }


            sequenceReader.ThrowIfNotEmpty();
        }
    }
}
