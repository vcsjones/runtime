// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Diagnostics;

namespace System.Security.Cryptography
{
    internal static class CryptoPool
    {
        internal const int ClearAll = -1;

        internal static byte[] Rent(int minimumLength) => ArrayPool<byte>.Shared.Rent(minimumLength);

        internal static void Return(ArraySegment<byte> arraySegment, int clearSize = ClearAll)
        {
            Debug.Assert(arraySegment.Array != null);
            Debug.Assert(arraySegment.Offset == 0);

            Return(arraySegment.Array, clearSize == ClearAll ? arraySegment.Count : clearSize);
        }

        internal static void Return(byte[] array, int clearSize = ClearAll)
        {
            Debug.Assert(clearSize <= array.Length);
            bool clearWholeArray = clearSize < 0;

            if (!clearWholeArray && clearSize != 0)
            {
#if (NET || NETSTANDARD2_1) && !CP_NO_ZEROMEMORY
                CryptographicOperations.ZeroMemory(array.AsSpan(0, clearSize));
#else
                Array.Clear(array, 0, clearSize);
#endif
            }

            ArrayPool<byte>.Shared.Return(array, clearWholeArray);
        }
    }
}
