// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Internal.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography
{
    internal abstract partial class AesGcmPal
    {
        private static Lazy<bool> s_HasCryptoKit = new Lazy<bool>(HasCryptoKit);

        public static AesGcmPal Create() => s_HasCryptoKit.Value ? (AesGcmPal)new AesGcmPalOSX() : (AesGcmPal)new AesGcmPalUnix();

        private static bool HasCryptoKit()
        {
            return false;
        }
    }
}
