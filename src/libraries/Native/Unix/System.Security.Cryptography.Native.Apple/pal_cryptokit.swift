// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

import Foundation
import CryptoKit

public final class PalCryptoKit
{
    // Not callable from pinvoke; uses Swift calling convention
    @_silgen_name("AppleCryptoNative_CryptoKit_AesGcm_Encrypt")
    public static func AppleCryptoNative_CryptoKit_AesGcm_Encrypt() -> Int32
    {
        return 1;
    }
}
