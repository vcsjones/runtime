// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Threading;
using System.Net;
using System.Net.Sockets;
using System.Linq;
using System.Security.Cryptography.X509Certificates.Tests.Common;
using Xunit;

namespace System.Security.Cryptography.X509Certificates.Tests.RevocationTests
{
    public static class AiaTests
    {
        [Theory]
        [InlineData(301)]
        [InlineData(302)]
        [InlineData(307)]
        [InlineData(308)]
        public static void AiaRedirectIsFollowed(int statusCode)
        {
            static string ConfigureAiaUrl(CertificateAuthority issuingAuthority)
            {
                Uri aiaUrl = new Uri(issuingAuthority.AiaHttpUri, UriKind.Absolute);
                Uri relativePath = new Uri("/banana", UriKind.Relative);
                Uri absoluteRedirect = new Uri(aiaUrl, relativePath);
                return absoluteRedirect.ToString();
            }

            CertificateAuthority.BuildPrivatePki(
                PkiOptions.AllRevocation,
                out RevocationResponder responder,
                out CertificateAuthority root,
                out CertificateAuthority intermediate,
                out X509Certificate2 endEntity,
                configureEeAiaUrl: ConfigureAiaUrl);

            using (responder)
            using (root)
            using (intermediate)
            using (endEntity)
            using (ChainHolder holder = new ChainHolder())
            using (X509Certificate2 rootCert = root.CloneIssuerCert())
            {
                Uri aiaUrl = new Uri(intermediate.AiaHttpUri, UriKind.Absolute);
                responder.InjectAiaRedirect(aiaUrl.AbsolutePath, "/banana");
                responder.RedirectStatusCode = statusCode;

                X509Chain chain = holder.Chain;
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.VerificationTime = endEntity.NotBefore.AddMinutes(1);
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.CustomTrustStore.Add(rootCert);

                Assert.True(chain.Build(endEntity));
            }
        }

        [Fact]
        public static void AiaHttpsRedirectIsNotFollowed()
        {
            using TcpListenerCounter cb = TcpListenerCounter.CreateAndConnect();

            CertificateAuthority.BuildPrivatePki(
                PkiOptions.AllRevocation,
                out RevocationResponder responder,
                out CertificateAuthority root,
                out CertificateAuthority intermediate,
                out X509Certificate2 endEntity,
                configureEeAiaUrl: null);

            using (responder)
            using (root)
            using (intermediate)
            using (endEntity)
            using (ChainHolder holder = new ChainHolder())
            using (X509Certificate2 rootCert = root.CloneIssuerCert())
            using (X509Certificate2 intermediateCert = intermediate.CloneIssuerCert())
            {
                Uri aiaUrl = new Uri(intermediate.AiaHttpUri, UriKind.Absolute);

                // The RevocationResponder will redirect to our TcpListener. We don't
                // really need a real HTTPS handshake and stuff, it's okay that the
                // TcpListner just closes that connection. All that we care about is that
                // it shouldn't even attempt to follow the HTTPS redirect so the connection
                // count should remain at zero.
                responder.InjectAiaRedirect(aiaUrl.AbsolutePath, $"https://127.0.0.1:{cb.BoundPort}");

                X509Chain chain = holder.Chain;
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.VerificationTime = endEntity.NotBefore.AddMinutes(1);
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.CustomTrustStore.Add(rootCert);

                Assert.False(chain.Build(endEntity));
                Assert.Equal(0, cb.ConnectionCount);
            }
        }

        [Fact]
        public static void EmptyAiaResponseIsIgnored()
        {
            CertificateAuthority.BuildPrivatePki(
                PkiOptions.AllRevocation,
                out RevocationResponder responder,
                out CertificateAuthority root,
                out CertificateAuthority intermediate,
                out X509Certificate2 endEntity,
                pkiOptionsInSubject: false);

            using (responder)
            using (root)
            using (intermediate)
            using (endEntity)
            using (ChainHolder holder = new ChainHolder())
            using (X509Certificate2 rootCert = root.CloneIssuerCert())
            using (X509Certificate2 intermediateCert = intermediate.CloneIssuerCert())
            {
                responder.RespondEmpty = true;

                X509Chain chain = holder.Chain;
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.VerificationTime = endEntity.NotBefore.AddMinutes(1);
                chain.ChainPolicy.UrlRetrievalTimeout = DynamicRevocationTests.s_urlRetrievalLimit;
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

                Assert.False(chain.Build(endEntity));
                Assert.True(chain.AllStatusFlags().HasFlag(X509ChainStatusFlags.PartialChain), "expected partial chain");
            }
        }

        [Fact]
        public static void DisableAiaOptionWorks()
        {
            CertificateAuthority.BuildPrivatePki(
                PkiOptions.AllRevocation,
                out RevocationResponder responder,
                out CertificateAuthority root,
                out CertificateAuthority intermediate,
                out X509Certificate2 endEntity,
                pkiOptionsInSubject: false);

            using (responder)
            using (root)
            using (intermediate)
            using (endEntity)
            using (ChainHolder holder = new ChainHolder())
            using (X509Certificate2 rootCert = root.CloneIssuerCert())
            using (X509Certificate2 intermediateCert = intermediate.CloneIssuerCert())
            using (var cuCaStore = new X509Store(StoreName.CertificateAuthority, StoreLocation.CurrentUser))
            {
                cuCaStore.Open(OpenFlags.ReadWrite);

                X509Chain chain = holder.Chain;
                chain.ChainPolicy.DisableCertificateDownloads = true;
                chain.ChainPolicy.CustomTrustStore.Add(rootCert);
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.VerificationTime = endEntity.NotBefore.AddMinutes(1);
                chain.ChainPolicy.UrlRetrievalTimeout = DynamicRevocationTests.s_urlRetrievalLimit;

                Assert.False(chain.Build(endEntity), "Chain build with no intermediate, AIA disabled");

                // If a previous run of this test leaves contamination in the CU\CA store on Windows
                // the Windows chain engine will match the bad issuer and report NotSignatureValid instead
                // of PartialChain.
                X509ChainStatusFlags chainFlags = chain.AllStatusFlags();

                if (chainFlags.HasFlag(X509ChainStatusFlags.NotSignatureValid))
                {
                    Assert.Equal(3, chain.ChainElements.Count);

                    foreach (X509Certificate2 storeCert in cuCaStore.Certificates)
                    {
                        if (storeCert.Subject.Equals(intermediateCert.Subject))
                        {
                            cuCaStore.Remove(storeCert);
                        }

                        storeCert.Dispose();
                    }

                    holder.DisposeChainElements();

                    // Try again, with no caching side effect.
                    Assert.False(chain.Build(endEntity), "Chain build 2 with no intermediate, AIA disabled");
                }

                Assert.Equal(1, chain.ChainElements.Count);
                Assert.Contains(X509ChainStatusFlags.PartialChain, chain.ChainStatus.Select(s => s.Status));
                holder.DisposeChainElements();

                // macOS doesn't like our revocation responder, so disable revocation checks there.
                if (PlatformDetection.IsOSX)
                {
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                }

                chain.ChainPolicy.ExtraStore.Add(intermediateCert);
                Assert.True(chain.Build(endEntity), "Chain build with intermediate, AIA disabled");
                Assert.Equal(3, chain.ChainElements.Count);
                Assert.Equal(X509ChainStatusFlags.NoError, chain.AllStatusFlags());
                holder.DisposeChainElements();

                chain.ChainPolicy.DisableCertificateDownloads = false;
                chain.ChainPolicy.ExtraStore.Clear();
                Assert.True(chain.Build(endEntity), "Chain build with no intermediate, AIA enabled");
                Assert.Equal(3, chain.ChainElements.Count);
                Assert.Equal(X509ChainStatusFlags.NoError, chain.AllStatusFlags());

                cuCaStore.Remove(intermediateCert);
            }
        }
    }

    internal sealed class TcpListenerCounter : IDisposable
    {
        private TcpListener _listener;
        private int _connectionCount;
        private volatile bool _listening;

        public int BoundPort { get; }
        public int ConnectionCount => _connectionCount;

        public TcpListenerCounter(TcpListener listener, int port)
        {
            _listener = listener;
            BoundPort = port;
            _listening = true;
        }

        public static TcpListenerCounter CreateAndConnect()
        {
            TcpListener listener = null;
            int port;

            while (true)
            {
                port = RandomNumberGenerator.GetInt32(41000, 42000);

                try
                {
                    listener = new TcpListener(IPAddress.Loopback, port);
                    listener.Start();
                    break;
                }
                catch (SocketException)
                {
                    listener.Stop();
                }
            }

            TcpListenerCounter counter = new TcpListenerCounter(listener, port);
            counter.StartCounting();
            return counter;
        }

        private void StartCounting()
        {
            ThreadPool.QueueUserWorkItem(
                static me =>
                {
                    while (me._listening)
                    {
                        try
                        {
                            TcpClient client = me._listener.AcceptTcpClient();
                            Interlocked.Increment(ref me._connectionCount);
                            client.Close();
                        }
                        catch
                        {
                            // Don't throw if we shut down while waiting.
                        }
                    }
                },
                this,
                true);
        }

        public void Dispose()
        {
            _listening = false;
            _listener.Stop();
        }
    }
}
