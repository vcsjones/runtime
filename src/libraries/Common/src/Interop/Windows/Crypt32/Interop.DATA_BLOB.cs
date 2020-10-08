// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.InteropServices;

internal partial class Interop
{
    internal partial class Crypt32
    {
        [StructLayout(LayoutKind.Sequential)]
        internal unsafe struct DATA_BLOB
        {
            internal uint cbData;
            internal byte* pbData;

            internal DATA_BLOB(byte* handle, uint size)
            {
                cbData = size;
                pbData = handle;
            }

            public byte[] ToByteArray()
            {
                if (cbData == 0)
                {
                    return Array.Empty<byte>();
                }

                int size = checked((int)cbData);
                byte[] array = new byte[size];
                Marshal.Copy((IntPtr)pbData, array, 0, size);
                return array;
            }
        }
    }
}
