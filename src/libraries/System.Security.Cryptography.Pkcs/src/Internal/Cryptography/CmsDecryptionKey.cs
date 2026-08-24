// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security.Cryptography;

#if !NET11_0_OR_GREATER
namespace System.Runtime.CompilerServices
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct, Inherited = false)]
    internal sealed class UnionAttribute : Attribute
    {
    }

    internal interface IUnion
    {
        object? Value { get; }
    }
}
#endif

namespace Internal.Cryptography
{
    internal union CmsDecryptionKey(AsymmetricAlgorithm, MLKem, CmsDecryptionKey.NoKey)
    {
        internal sealed record NoKey;
    }
}
