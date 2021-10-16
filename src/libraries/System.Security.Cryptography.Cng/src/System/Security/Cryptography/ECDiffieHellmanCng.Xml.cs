// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Security.Cryptography
{
    public sealed partial class ECDiffieHellmanCng : ECDiffieHellman
    {
        [Obsolete(Obsoletions.ToFromXmlStringEcMessage, DiagnosticId = Obsoletions.ToFromXmlStringEcDiagId, UrlFormat = Obsoletions.SharedUrlFormat)]
        public void FromXmlString(string xml, ECKeyXmlFormat format)
        {
            throw new PlatformNotSupportedException();
        }

        [Obsolete(Obsoletions.ToFromXmlStringEcMessage, DiagnosticId = Obsoletions.ToFromXmlStringEcDiagId, UrlFormat = Obsoletions.SharedUrlFormat)]
        public string ToXmlString(ECKeyXmlFormat format)
        {
            throw new PlatformNotSupportedException();
        }
    }
}
