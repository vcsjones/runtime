namespace System.Security.Cryptography;

public partial struct HashAlgorithmName {
    public static HashAlgorithmName SHA3_256 { get; }
    public static HashAlgorithmName SHA3_384 { get; }
    public static HashAlgorithmName SHA3_512 { get; }
}

public sealed partial class RSAEncryptionPadding {
    public static RSAEncryptionPadding OaepSHA3_256 { get; }
    public static RSAEncryptionPadding OaepSHA3_384 { get; }
    public static RSAEncryptionPadding OaepSHA3_512 { get; }
}

public abstract partial class SHA3_256 : HashAlgorithm {
    public const int HashSizeInBits = 256;
    public const int HashSizeInBytes = 32;

    protected SHA3_256();

    public static bool IsSupported { get; }

    public static new SHA3_256 Create();

    public static byte[] HashData(byte[] source);
    public static byte[] HashData(ReadOnlySpan<byte> source);
    public static int HashData(ReadOnlySpan<byte> source, Span<byte> destination);
    public static bool TryHashData(ReadOnlySpan<byte> source, Span<byte> destination, out int bytesWritten);

    public static byte[] HashData(Stream source);
    public static int HashData(Stream source, Span<byte> destination);
    public static ValueTask<int> HashDataAsync(Stream source, Memory<byte> destination, CancellationToken cancellationToken = default);
    public static ValueTask<byte[]> HashDataAsync(Stream source, CancellationToken cancellationToken = default);
}


public abstract partial class SHA3_384 : HashAlgorithm {
    public const int HashSizeInBits = 384;
    public const int HashSizeInBytes = 48;

    protected SHA3_384();

    public static bool IsSupported { get; }

    public static new SHA3_384 Create();

    public static byte[] HashData(byte[] source);
    public static byte[] HashData(ReadOnlySpan<byte> source);
    public static int HashData(ReadOnlySpan<byte> source, Span<byte> destination);
    public static bool TryHashData(ReadOnlySpan<byte> source, Span<byte> destination, out int bytesWritten);

    public static byte[] HashData(Stream source);
    public static int HashData(Stream source, Span<byte> destination);
    public static ValueTask<int> HashDataAsync(Stream source, Memory<byte> destination, CancellationToken cancellationToken = default);
    public static ValueTask<byte[]> HashDataAsync(Stream source, CancellationToken cancellationToken = default);
}

public abstract partial class SHA3_512 : HashAlgorithm {
    public const int HashSizeInBits = 512;
    public const int HashSizeInBytes = 64;

    protected SHA3_512();

    public static bool IsSupported { get; }

    public static new SHA3_512 Create();

    public static byte[] HashData(byte[] source);
    public static byte[] HashData(ReadOnlySpan<byte> source);
    public static int HashData(ReadOnlySpan<byte> source, Span<byte> destination);
    public static bool TryHashData(ReadOnlySpan<byte> source, Span<byte> destination, out int bytesWritten);

    public static byte[] HashData(Stream source);
    public static int HashData(Stream source, Span<byte> destination);
    public static ValueTask<int> HashDataAsync(Stream source, Memory<byte> destination, CancellationToken cancellationToken = default);
    public static ValueTask<byte[]> HashDataAsync(Stream source, CancellationToken cancellationToken = default);
}


public partial class HMACSHA3_256 : HMAC {
    public const int HashSizeInBits = 256;
    public const int HashSizeInBytes = 32;

    public HMACSHA3_256();
    public HMACSHA3_256(byte[] key);

    public static bool IsSupported { get; } // New

    public static byte[] HashData(byte[] key, byte[] source);
    public static byte[] HashData(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source);
    public static int HashData(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination);
    public static bool TryHashData(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination, out int bytesWritten);

    public static byte[] HashData(byte[] key, Stream source);
    public static byte[] HashData(ReadOnlySpan<byte> key, Stream source);
    public static int HashData(ReadOnlySpan<byte> key, Stream source, Span<byte> destination);

    public static ValueTask<byte[]> HashDataAsync(byte[] key, Stream source, CancellationToken cancellationToken = default);
    public static ValueTask<int> HashDataAsync(ReadOnlyMemory<byte> key, Stream source, Memory<byte> destination, CancellationToken cancellationToken = default);
    public static ValueTask<byte[]> HashDataAsync(ReadOnlyMemory<byte> key, Stream source, CancellationToken cancellationToken = default);
}

public partial class HMACSHA3_384 : HMAC {
    public const int HashSizeInBits = 384;
    public const int HashSizeInBytes = 48;

    public HMACSHA3_384();
    public HMACSHA3_384(byte[] key);

    public static bool IsSupported { get; } // New

    public static byte[] HashData(byte[] key, byte[] source);
    public static byte[] HashData(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source);
    public static int HashData(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination);
    public static bool TryHashData(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination, out int bytesWritten);

    public static byte[] HashData(byte[] key, Stream source);
    public static byte[] HashData(ReadOnlySpan<byte> key, Stream source);
    public static int HashData(ReadOnlySpan<byte> key, Stream source, Span<byte> destination);

    public static ValueTask<byte[]> HashDataAsync(byte[] key, Stream source, CancellationToken cancellationToken = default);
    public static ValueTask<int> HashDataAsync(ReadOnlyMemory<byte> key, Stream source, Memory<byte> destination, CancellationToken cancellationToken = default);
    public static ValueTask<byte[]> HashDataAsync(ReadOnlyMemory<byte> key, Stream source, CancellationToken cancellationToken = default);
}

public partial class HMACSHA3_512 : HMAC {
    public const int HashSizeInBits = 512;
    public const int HashSizeInBytes = 64;

    public HMACSHA3_512();
    public HMACSHA3_512(byte[] key);

    public static bool IsSupported { get; } // New

    public static byte[] HashData(byte[] key, byte[] source);
    public static byte[] HashData(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source);
    public static int HashData(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination);
    public static bool TryHashData(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination, out int bytesWritten);

    public static byte[] HashData(byte[] key, Stream source);
    public static byte[] HashData(ReadOnlySpan<byte> key, Stream source);
    public static int HashData(ReadOnlySpan<byte> key, Stream source, Span<byte> destination);

    public static ValueTask<byte[]> HashDataAsync(byte[] key, Stream source, CancellationToken cancellationToken = default);
    public static ValueTask<int> HashDataAsync(ReadOnlyMemory<byte> key, Stream source, Memory<byte> destination, CancellationToken cancellationToken = default);
    public static ValueTask<byte[]> HashDataAsync(ReadOnlyMemory<byte> key, Stream source, CancellationToken cancellationToken = default);
}

public abstract partial class Shake : IDisposable {
    internal Shake(); // Will not be subclassable by developers.

    public void AppendData(byte[] data);
    public void AppendData(ReadOnlySpan<byte> data);

    public byte[] GetCurrentHash(int outputLength);
    public void GetCurrentHash(Span<byte> destination);
    public byte[] GetHashAndReset(int outputLength);
    public void GetHashAndReset(Span<byte> destination);

    public void Dispose();
}

public sealed partial class Shake128 : Shake {
    public Shake128();

    public static bool IsSupported { get; }

    public static byte[] HashData(byte[] source, int outputLength);
    public static byte[] HashData(ReadOnlySpan<byte> source, int outputLength);
    public static void HashData(ReadOnlySpan<byte> source, Span<byte> destination);

    public static byte[] HashData(Stream source, int outputLength);
    public static void HashData(Stream source, Span<byte> destination);
    public static ValueTask HashDataAsync(Stream source, Memory<byte> destination, CancellationToken cancellationToken = default);
    public static ValueTask<byte[]> HashDataAsync(Stream source, int outputLength, CancellationToken cancellationToken = default);
}

public sealed partial class Shake256 : Shake {
    public Shake256();

    public static bool IsSupported { get; }

    public static byte[] HashData(byte[] source, int outputLength);
    public static byte[] HashData(ReadOnlySpan<byte> source, int outputLength);
    public static void HashData(ReadOnlySpan<byte> source, Span<byte> destination);

    public static byte[] HashData(Stream source, int outputLength);
    public static void HashData(Stream source, Span<byte> destination);
    public static ValueTask HashDataAsync(Stream source, Memory<byte> destination, CancellationToken cancellationToken = default);
    public static ValueTask<byte[]> HashDataAsync(Stream source, int outputLength, CancellationToken cancellationToken = default);
}