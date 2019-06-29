// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Internal.Cryptography;
using Internal.NativeCrypto;
using static Interop.BCrypt;

namespace System.Security.Cryptography
{
    internal abstract partial class AesGcmPal
    {
        public static AesGcmPal Create() => new AesGcmPalWindows();
    }
}
