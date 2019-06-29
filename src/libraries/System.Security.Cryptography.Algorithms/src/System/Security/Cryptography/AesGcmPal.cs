namespace System.Security.Cryptography
{
    internal abstract partial class AesGcmPal : IDisposable
    {
        public abstract void ImportKey(ReadOnlySpan<byte> key);

        public const int NonceSize = 12;
        public static KeySizes NonceByteSizes { get; } = new KeySizes(NonceSize, NonceSize, 1);
        public static KeySizes TagByteSizes { get; } = new KeySizes(12, 16, 1);

        public abstract void Encrypt(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            Span<byte> tag,
            ReadOnlySpan<byte> associatedData = default);

        public abstract void Decrypt(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> tag,
            Span<byte> plaintext,
            ReadOnlySpan<byte> associatedData = default);

        public abstract void Dispose();
    }
}
