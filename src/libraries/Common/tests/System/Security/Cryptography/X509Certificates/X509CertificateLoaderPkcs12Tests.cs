// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.IO;
using System.IO.MemoryMappedFiles;
using Xunit;

namespace System.Security.Cryptography.X509Certificates.Tests
{
    public class X509CertificateLoaderPkcs12Tests_FromByteArray : X509CertificateLoaderPkcs12Tests
    {
        protected override void NullInputAssert(Action action) =>
            AssertExtensions.Throws<ArgumentNullException>("data", action);

        protected override void EmptyInputAssert(Action action) =>
            Assert.Throws<CryptographicException>(action);

        protected override X509Certificate2 LoadPfxCore(
            byte[] bytes,
            string path,
            string password,
            X509KeyStorageFlags keyStorageFlags,
            Pkcs12LoaderLimits loaderLimits)
        {
            return X509CertificateLoader.LoadPkcs12(bytes, password, keyStorageFlags, loaderLimits);
        }

        protected override X509Certificate2 LoadPfxFileOnlyCore(
            string path,
            string password,
            X509KeyStorageFlags keyStorageFlags,
            Pkcs12LoaderLimits loaderLimits)
        {
            return X509CertificateLoader.LoadPkcs12(
                File.ReadAllBytes(path),
                password,
                keyStorageFlags,
                loaderLimits);
        }

        protected override bool TryGetContentType(byte[] bytes, string path, out X509ContentType contentType)
        {
            if (bytes is null)
            {
                contentType = X509ContentType.Unknown;
                return false;
            }

            contentType = X509Certificate2.GetCertContentType(bytes);
            return true;
        }
    }

    public class X509CertificateLoaderPkcs12Tests_FromByteSpan : X509CertificateLoaderPkcs12Tests
    {
        protected override void NullInputAssert(Action action) =>
            Assert.ThrowsAny<CryptographicException>(action);

        protected override void EmptyInputAssert(Action action) =>
            Assert.ThrowsAny<CryptographicException>(action);

        protected override X509Certificate2 LoadPfxCore(
            byte[] bytes,
            string path,
            string password,
            X509KeyStorageFlags keyStorageFlags,
            Pkcs12LoaderLimits loaderLimits)
        {
            return X509CertificateLoader.LoadPkcs12(
                new ReadOnlySpan<byte>(bytes),
                password,
                keyStorageFlags,
                loaderLimits);
        }

        protected override X509Certificate2 LoadPfxAtOffsetCore(
            byte[] bytes,
            int offset,
            string password,
            X509KeyStorageFlags keyStorageFlags,
            Pkcs12LoaderLimits loaderLimits)
        {
            return X509CertificateLoader.LoadPkcs12(
                bytes.AsSpan(offset),
                password,
                keyStorageFlags,
                loaderLimits);
        }

        protected override X509Certificate2 LoadPfxFileOnlyCore(
            string path,
            string password,
            X509KeyStorageFlags keyStorageFlags,
            Pkcs12LoaderLimits loaderLimits)
        {
            // Use a fancy strategy other than File.ReadAllBytes.

            using (FileStream stream = File.OpenRead(path))
            using (MemoryMappedFile mapped = MemoryMappedFile.CreateFromFile(
                stream,
                null,
                stream.Length,
                MemoryMappedFileAccess.Read,
                HandleInheritability.None,
                false))
            {
                using (MemoryMappedViewAccessor view = mapped.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read))
                {
                    unsafe
                    {
                        byte* pointer = null;

                        try
                        {
                            view.SafeMemoryMappedViewHandle.AcquirePointer(ref pointer);

                            using (var manager = new PointerMemoryManager<byte>(pointer, checked((int)stream.Length)))
                            {
                                return X509CertificateLoader.LoadPkcs12(
                                    manager.Memory.Span,
                                    password,
                                    keyStorageFlags,
                                    loaderLimits);
                            }
                        }
                        finally
                        {
                            if (pointer != null)
                            {
                                view.SafeMemoryMappedViewHandle.ReleasePointer();
                            }
                        }
                    }
                }
            }
        }

        protected override bool TryGetContentType(byte[] bytes, string path, out X509ContentType contentType)
        {
            contentType = X509ContentType.Unknown;
            return false;
        }
    }

    public class X509CertificateLoaderPkcs12Tests_FromFile : X509CertificateLoaderPkcs12Tests
    {
        protected override void NullInputAssert(Action action) =>
            AssertExtensions.Throws<ArgumentNullException>("path", action);

        protected override void EmptyInputAssert(Action action) =>
            AssertExtensions.Throws<ArgumentException>("path", action);

        protected override X509Certificate2 LoadPfxCore(
            byte[] bytes,
            string path,
            string password,
            X509KeyStorageFlags keyStorageFlags,
            Pkcs12LoaderLimits loaderLimits)
        {
            return X509CertificateLoader.LoadPkcs12FromFile(path, password, keyStorageFlags, loaderLimits);
        }

        protected override X509Certificate2 LoadPfxFileOnlyCore(
            string path,
            string password,
            X509KeyStorageFlags keyStorageFlags,
            Pkcs12LoaderLimits loaderLimits)
        {
            return X509CertificateLoader.LoadCertificateFromFile(path);
        }

        protected override X509Certificate2 LoadPfxNoFileCore(
            byte[] bytes,
            string password,
            X509KeyStorageFlags keyStorageFlags,
            Pkcs12LoaderLimits loaderLimits)
        {
            string path = Path.GetTempFileName();

            try
            {
                File.WriteAllBytes(path, bytes);
                return LoadPfx(bytes, path, password, keyStorageFlags, loaderLimits);
            }
            finally
            {
                File.Delete(path);
            }
        }

        protected override bool TryGetContentType(byte[] bytes, string path, out X509ContentType contentType)
        {
            if (path is null)
            {
                contentType = X509ContentType.Unknown;
                return false;
            }

            contentType = X509Certificate2.GetCertContentType(path);
            return true;
        }
    }

    public abstract class X509CertificateLoaderPkcs12Tests
    {
        private const int ERROR_INVALID_PASSWORD = -2147024810;

        protected static readonly X509KeyStorageFlags EphemeralIfPossible =
            PlatformDetection.UsesAppleCrypto ? 
                X509KeyStorageFlags.DefaultKeySet :
                X509KeyStorageFlags.EphemeralKeySet;

        protected abstract void NullInputAssert(Action action);
        protected abstract void EmptyInputAssert(Action action);

        protected X509Certificate2 LoadPfx(
            byte[] bytes,
            string path,
            string password = "",
            X509KeyStorageFlags? keyStorageFlags = null,
            Pkcs12LoaderLimits loaderLimits = null)
        {
            return LoadPfxCore(
                bytes,
                path,
                password,
                keyStorageFlags.GetValueOrDefault(EphemeralIfPossible),
                loaderLimits);
        }

        protected abstract X509Certificate2 LoadPfxCore(
            byte[] bytes,
            string path,
            string password,
            X509KeyStorageFlags keyStorageFlags,
            Pkcs12LoaderLimits loaderLimits);

        protected X509Certificate2 LoadPfxFileOnly(
            string path,
            string password = "",
            X509KeyStorageFlags? keyStorageFlags = null,
            Pkcs12LoaderLimits loaderLimits = null)
        {
            return LoadPfxFileOnlyCore(
                path,
                password,
                keyStorageFlags.GetValueOrDefault(EphemeralIfPossible),
                loaderLimits);
        }

        protected abstract X509Certificate2 LoadPfxFileOnlyCore(
            string path,
            string password,
            X509KeyStorageFlags keyStorageFlags,
            Pkcs12LoaderLimits loaderLimits);

        protected virtual X509Certificate2 LoadPfxNoFile(
            byte[] bytes,
            string password = "",
            X509KeyStorageFlags? keyStorageFlags = null,
            Pkcs12LoaderLimits loaderLimits = null)
        {
            return LoadPfxNoFileCore(
                bytes,
                password,
                keyStorageFlags.GetValueOrDefault(EphemeralIfPossible),
                loaderLimits);
        }

        protected virtual X509Certificate2 LoadPfxNoFileCore(
            byte[] bytes,
            string password,
            X509KeyStorageFlags keyStorageFlags,
            Pkcs12LoaderLimits loaderLimits)
        {
            return LoadPfx(bytes, null, password, keyStorageFlags, loaderLimits);
        }

        protected virtual X509Certificate2 LoadPfxAtOffset(
            byte[] bytes,
            int offset,
            string password = "",
            X509KeyStorageFlags? keyStorageFlags = null,
            Pkcs12LoaderLimits loaderLimits = null)
        {
            return LoadPfxAtOffsetCore(
                bytes,
                offset,
                password,
                keyStorageFlags.GetValueOrDefault(EphemeralIfPossible),
                loaderLimits);
        }

        protected virtual X509Certificate2 LoadPfxAtOffsetCore(
            byte[] bytes,
            int offset,
            string password,
            X509KeyStorageFlags keyStorageFlags,
            Pkcs12LoaderLimits loaderLimits)
        {
            return LoadPfxNoFile(
                bytes.AsSpan(offset).ToArray(),
                password,
                keyStorageFlags,
                loaderLimits);
        }

        protected abstract bool TryGetContentType(byte[] bytes, string path, out X509ContentType contentType);

        [Fact]
        public void LoadNull()
        {
            NullInputAssert(() => LoadPfx(null, null, null));
        }

        [Fact]
        public void LoadEmpty()
        {
            EmptyInputAssert(() => LoadPfx(Array.Empty<byte>(), string.Empty));
        }

        private void LoadKnownFormat_Fails(byte[] data, string path, X509ContentType contentType)
        {
            if (TryGetContentType(data, path, out X509ContentType actualType))
            {
                Assert.Equal(contentType, actualType);
            }
            
            if (path is null)
            {
                Assert.ThrowsAny<CryptographicException>(() => LoadPfxNoFile(data));
            }
            else if (data is null)
            {
                Assert.ThrowsAny<CryptographicException>(() => LoadPfxFileOnly(path));
            }
            else
            {
                Assert.ThrowsAny<CryptographicException>(() => LoadPfx(data, path));
            }
        }

        [Fact]
        public void LoadCertificate_DER_Fails()
        {
            LoadKnownFormat_Fails(TestData.MsCertificate, TestFiles.MsCertificateDerFile, X509ContentType.Cert);
        }

        [Fact]
        public void LoadCertificate_PEM_Fails()
        {
            LoadKnownFormat_Fails(TestData.MsCertificatePemBytes, TestFiles.MsCertificatePemFile, X509ContentType.Cert);
        }

        [Fact]
        public void LoadPkcs7_BER_Fails()
        {
            LoadKnownFormat_Fails(TestData.Pkcs7ChainDerBytes, TestFiles.Pkcs7ChainDerFile, X509ContentType.Pkcs7);
        }

        [Fact]
        public void LoadPkcs7_PEM_Fails()
        {
            LoadKnownFormat_Fails(TestData.Pkcs7ChainPemBytes, TestFiles.Pkcs7ChainPemFile, X509ContentType.Pkcs7);
        }
        
        [Fact]
        public void LoadSignedFile_Fails()
        {
            LoadKnownFormat_Fails(null, TestFiles.SignedMsuFile, X509ContentType.Authenticode);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void LoadPfx_Single_WithPassword(bool ignorePrivateKeys)
        {
            Pkcs12LoaderLimits loaderLimits = new Pkcs12LoaderLimits(Pkcs12LoaderLimits.Defaults)
            {
                IgnorePrivateKeys = ignorePrivateKeys,
            };

            X509Certificate2 cert = LoadPfx(
                TestData.PfxData,
                TestFiles.PfxFile,
                TestData.PfxDataPassword,
                EphemeralIfPossible,
                loaderLimits);

            using (cert)
            {
                Assert.Equal("CN=MyName", cert.Subject);
                Assert.NotEqual(ignorePrivateKeys, cert.HasPrivateKey);
            }
        }

        [Theory]
        [InlineData(true, true)]
        [InlineData(true, false)]
        [InlineData(false, true)]
        [InlineData(false, false)]
        public void LoadPfx_Single_NoPassword(bool ignorePrivateKeys, bool useNull)
        {
            Pkcs12LoaderLimits loaderLimits = new Pkcs12LoaderLimits(Pkcs12LoaderLimits.Defaults)
            {
                IgnorePrivateKeys = ignorePrivateKeys,
            };

            string password = useNull ? null : "";

            X509Certificate2 cert = LoadPfxNoFile(
                TestData.PfxWithNoPassword,
                password,
                EphemeralIfPossible,
                loaderLimits);

            using (cert)
            {
                Assert.Equal("CN=MyName", cert.Subject);
                Assert.NotEqual(ignorePrivateKeys, cert.HasPrivateKey);
            }
        }

        [Fact]
        public void LoadPfx_Single_WrongPassword()
        {
            CryptographicException ex = Assert.Throws<CryptographicException>(
                () => LoadPfx(TestData.PfxData, TestFiles.PfxFile, "asdf"));

            Assert.Contains("password", ex.Message);
            Assert.Equal(ERROR_INVALID_PASSWORD, ex.HResult);
        }

        [Fact]
        public void LoadPfx_WithTrailingData()
        {
            byte[] data = TestData.PfxWithNoPassword;
            Array.Resize(ref data, data.Length + 10);

            using (X509Certificate2 cert = LoadPfxNoFile(data))
            {
                Assert.Equal("CN=MyName", cert.Subject);
            }
        }
    }
}
