// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Microsoft.Win32.SafeHandles;
using System.Diagnostics;

namespace System.Security.Cryptography
{
    internal static partial class ECCng
    {
        internal static unsafe void RoundTripFullPrivateBlob(ref ECParameters ecParameters, bool ecdh)
        {
            string blobType = Interop.BCrypt.KeyBlobType.BCRYPT_ECCFULLPRIVATE_BLOB;
            byte[] blob = GetPrimeCurveBlob(ref ecParameters, ecdh);
            using SafeNCryptKeyHandle keyHandle = CngKeyLite.ImportKeyBlob(blobType, blob);
            Debug.Assert(!keyHandle.IsInvalid);
            byte[] exportBlob = CngKeyLite.ExportKeyBlob(keyHandle, blobType);
            ExportPrimeCurveParameters(ref ecParameters, exportBlob, includePrivateParameters: true);
        }
    }
}