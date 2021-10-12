// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Reflection;

namespace System.Security.Cryptography
{
    // This class allows accessing PemEncoding through reflection due to cyclic
    // assembly dependencies.
    // This should be removed when https://github.com/dotnet/runtime/issues/55690
    // is complete.
    internal static class PemEncodingWrapper
    {
        private delegate bool TryWriteFunc(ReadOnlySpan<char> label, ReadOnlySpan<byte> data, Span<char> destination, out int charsWritten);
        private static readonly TryWriteFunc _tryWrite = GetPemEncodingMethod<TryWriteFunc>("TryWrite");
        private static readonly Func<int, int, int> _getEncodedSize = GetPemEncodingMethod<Func<int, int, int>>("GetEncodedSize");

        private static T GetPemEncodingMethod<T>(string name) where T : System.Delegate
        {
            Type? pemEncodingType = Type.GetType("System.Security.Cryptography.PemEncoding, System.Security.Cryptography.Encoding, Version=5.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a", throwOnError: false);
            MethodInfo? method = pemEncodingType?.GetMethod(name);

            if (method is null)
            {
                Debug.Fail($"{name} method is unexpectedly not available.");
                throw new CryptographicException();
            }

            return (T)method.CreateDelegate(typeof(T));
        }

        internal static bool TryWrite(ReadOnlySpan<char> label, ReadOnlySpan<byte> data, Span<char> destination, out int charsWritten)
        {
            return _tryWrite(label, data, destination, out charsWritten);
        }

        internal static int GetEncodedSize(int labelLength, int dataLength)
        {
            return _getEncodedSize(labelLength, dataLength);
        }
    }
}
