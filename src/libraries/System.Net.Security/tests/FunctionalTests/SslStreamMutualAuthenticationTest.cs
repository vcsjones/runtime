// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IO;
using System.Threading.Tasks;
using System.Net.Test.Common;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Xunit;

namespace System.Net.Security.Tests
{
    using Configuration = System.Net.Test.Common.Configuration;

    public class SslStreamMutualAuthenticationTest : IDisposable
    {
        private readonly X509Certificate2 _clientCertificate;
        private readonly X509Certificate2 _serverCertificate;
        private readonly X509Certificate2 _selfSignedCertificate;

        public SslStreamMutualAuthenticationTest()
        {
            _serverCertificate = Configuration.Certificates.GetServerCertificate();
            _clientCertificate = Configuration.Certificates.GetClientCertificate();
            _selfSignedCertificate = Configuration.Certificates.GetSelfSignedServerCertificate();
        }

        public void Dispose()
        {
            _serverCertificate.Dispose();
            _clientCertificate.Dispose();
        }

        public enum ClientCertSource
        {
            ClientCertificate,
            SelectionCallback,
            CertificateContext
        }

        public enum CertificateExportBeforeUse
        {
            ExportPkcs12ContentType,
            ExportPkcs12ExportPbeParameters,
            ExportPkcs12PbeParameters
        }

        public static TheoryData<ClientCertSource> CertSourceData()
        {
            TheoryData<ClientCertSource> data = new();

            foreach (var source in Enum.GetValues<ClientCertSource>())
            {
                data.Add(source);
            }

            return data;
        }


        public static TheoryData<bool, ClientCertSource> BoolAndCertSourceData()
        {
            TheoryData<bool, ClientCertSource> data = new();

            foreach (var source in Enum.GetValues<ClientCertSource>())
            {
                data.Add(true, source);
                data.Add(false, source);
            }

            return data;
        }

        [Theory]
        [MemberData(nameof(BoolAndCertSourceData))]
        public async Task SslStream_RequireClientCert_IsMutuallyAuthenticated_ReturnsTrue(bool clientCertificateRequired, ClientCertSource certSource)
        {
            (Stream stream1, Stream stream2) = TestHelper.GetConnectedStreams();
            using (var client = new SslStream(stream1, false, AllowAnyCertificate))
            using (var server = new SslStream(stream2, false, AllowAnyCertificate))
            {
                var clientOptions = new SslClientAuthenticationOptions
                {
                    TargetHost = Guid.NewGuid().ToString("N")
                };

                switch (certSource)
                {
                    case ClientCertSource.ClientCertificate:
                        clientOptions.ClientCertificates = new X509CertificateCollection() { _clientCertificate };
                        break;
                    case ClientCertSource.SelectionCallback:
                        clientOptions.LocalCertificateSelectionCallback = ClientCertSelectionCallback;
                        break;
                    case ClientCertSource.CertificateContext:
                        clientOptions.ClientCertificateContext = SslStreamCertificateContext.Create(_clientCertificate, new());
                        break;
                }

                Task t2 = client.AuthenticateAsClientAsync(clientOptions);
                Task t1 = server.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = _serverCertificate,
                    ClientCertificateRequired = clientCertificateRequired
                });

                await TestConfiguration.WhenAllOrAnyFailedWithTimeout(t1, t2);

                if (clientCertificateRequired)
                {
                    Assert.True(client.IsMutuallyAuthenticated, "client.IsMutuallyAuthenticated");
                    Assert.True(server.IsMutuallyAuthenticated, "server.IsMutuallyAuthenticated");
                }
                else
                {
                    // Even though the certificate was provided, it was not requested by the server and thus the client
                    // was not authenticated.
                    Assert.False(client.IsMutuallyAuthenticated, "client.IsMutuallyAuthenticated");
                    Assert.False(server.IsMutuallyAuthenticated, "server.IsMutuallyAuthenticated");
                }
            }

            // Assert that the certificates are not being disposed
            Assert.NotEqual(_clientCertificate.Handle, IntPtr.Zero);
            Assert.NotEqual(_serverCertificate.Handle, IntPtr.Zero);
        }

        [Theory]
        [InlineData(CertificateExportBeforeUse.ExportPkcs12ContentType)]
        [InlineData(CertificateExportBeforeUse.ExportPkcs12ExportPbeParameters)]
        [InlineData(CertificateExportBeforeUse.ExportPkcs12PbeParameters)]
        [PlatformSpecific(TestPlatforms.Windows)]
        [OuterLoop("Modifies user-persisted state", ~TestPlatforms.Browser)]
        public async Task SslStream_ClientCertificateExportedAsPkcs12BeforeUse_IsMutuallyAuthenticated(
            CertificateExportBeforeUse exportBeforeUse)
        {
            string commonName = $"{nameof(SslStream_ClientCertificateExportedAsPkcs12BeforeUse_IsMutuallyAuthenticated)}-{Guid.NewGuid():N}";
            string subject = $"CN={commonName}, OU=.NET";
            string keyName = $"clrtest.{commonName}";

            using X509Store currentUserMy = new(StoreName.My, StoreLocation.CurrentUser);
            currentUserMy.Open(OpenFlags.ReadWrite);

            X509Certificate2? createdCertificate = null;
            X509Certificate2? clientCertificate = null;

            try
            {
                RemoveCertificatesBySubjectName(currentUserMy, commonName);

                createdCertificate = CreatePersistedClientCertificate(subject, keyName);
                currentUserMy.Add(createdCertificate);

                clientCertificate = FindSingleCertificateBySubjectName(currentUserMy, commonName);
                Assert.True(clientCertificate.HasPrivateKey);

                ExportAsPkcs12(clientCertificate, exportBeforeUse);
                await AuthenticateWithClientCertificate(clientCertificate);
            }
            finally
            {
                RemoveCertificatesBySubjectName(currentUserMy, commonName);
                clientCertificate?.Dispose();
                createdCertificate?.Dispose();

                try
                {
                    using CngKey key = CngKey.Open(keyName);
                    key.Delete();
                }
                catch (CryptographicException)
                {
                }
            }
        }

        private async Task AuthenticateWithClientCertificate(X509Certificate2 clientCertificate)
        {
            (Stream stream1, Stream stream2) = TestHelper.GetConnectedStreams();
            using (var client = new SslStream(stream1, false, AllowAnyCertificate))
            using (var server = new SslStream(stream2, false, AllowAnyCertificate))
            {
                var clientOptions = new SslClientAuthenticationOptions
                {
                    ClientCertificates = new X509CertificateCollection() { clientCertificate },
                    TargetHost = Guid.NewGuid().ToString("N")
                };

                var serverOptions = new SslServerAuthenticationOptions
                {
                    ServerCertificate = _serverCertificate,
                    ClientCertificateRequired = true
                };

                Task t2 = client.AuthenticateAsClientAsync(clientOptions);
                Task t1 = server.AuthenticateAsServerAsync(serverOptions);

                await TestConfiguration.WhenAllOrAnyFailedWithTimeout(t1, t2);

                Assert.True(client.IsMutuallyAuthenticated, "client.IsMutuallyAuthenticated");
                Assert.True(server.IsMutuallyAuthenticated, "server.IsMutuallyAuthenticated");
            }
        }

        private static X509Certificate2 CreatePersistedClientCertificate(string subject, string keyName)
        {
            CngKeyCreationParameters options = new()
            {
                ExportPolicy = CngExportPolicies.AllowExport | CngExportPolicies.AllowPlaintextExport,
            };

            using CngKey key = CngKey.Create(CngAlgorithm.Rsa, keyName, options);
            using RSACng rsaCng = new(key);
            CertificateRequest certReq = new(
                subject,
                rsaCng,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            certReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            certReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") },
                false));
            certReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));

            DateTimeOffset now = DateTimeOffset.UtcNow.AddMinutes(-5);
            return certReq.CreateSelfSigned(now, now.AddDays(1));
        }

        private static X509Certificate2 FindSingleCertificateBySubjectName(X509Store store, string subjectName)
        {
            X509Certificate2Collection matches = store.Certificates.Find(
                X509FindType.FindBySubjectName,
                subjectName,
                validOnly: false);

            Assert.Equal(1, matches.Count);
            X509Certificate2 result = matches[0];

            for (int i = 1; i < matches.Count; i++)
            {
                matches[i].Dispose();
            }

            return result;
        }

        private static void RemoveCertificatesBySubjectName(X509Store store, string subjectName)
        {
            X509Certificate2Collection matches = store.Certificates.Find(
                X509FindType.FindBySubjectName,
                subjectName,
                validOnly: false);

            foreach (X509Certificate2 match in matches)
            {
                store.Remove(match);
                match.Dispose();
            }
        }

        private static void ExportAsPkcs12(X509Certificate2 certificate, CertificateExportBeforeUse exportBeforeUse)
        {
            switch (exportBeforeUse)
            {
                case CertificateExportBeforeUse.ExportPkcs12ContentType:
                    Assert.NotNull(certificate.Export(X509ContentType.Pkcs12));
                    break;
                case CertificateExportBeforeUse.ExportPkcs12ExportPbeParameters:
                    Assert.NotNull(certificate.ExportPkcs12(Pkcs12ExportPbeParameters.Pkcs12TripleDesSha1, null));
                    break;
                case CertificateExportBeforeUse.ExportPkcs12PbeParameters:
                    Assert.NotNull(certificate.ExportPkcs12(
                        new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 32),
                        null));
                    break;
                default:
                    Assert.Fail($"Unexpected export operation: {exportBeforeUse}");
                    break;
            }
        }

        [Theory]
        [ClassData(typeof(SslProtocolSupport.SupportedSslProtocolsTestData))]
        public async Task SslStream_CachedCredentials_IsMutuallyAuthenticatedCorrect(
           SslProtocols protocol)
        {
            var clientOptions = new SslClientAuthenticationOptions
            {
                ClientCertificates = new X509CertificateCollection() { _clientCertificate },
                EnabledSslProtocols = protocol,
                RemoteCertificateValidationCallback = delegate { return true; },
                TargetHost = Guid.NewGuid().ToString("N")
            };

            for (int i = 0; i < 5; i++)
            {
                (SslStream client, SslStream server) = TestHelper.GetConnectedSslStreams();
                using (client)
                using (server)
                {
                    bool expectMutualAuthentication = (i % 2) == 0;

                    var serverOptions = new SslServerAuthenticationOptions
                    {
                        ClientCertificateRequired = expectMutualAuthentication,
                        ServerCertificate = expectMutualAuthentication ? _serverCertificate : _selfSignedCertificate,
                        RemoteCertificateValidationCallback = delegate { return true; },
                        EnabledSslProtocols = protocol
                    };

                    await TestConfiguration.WhenAllOrAnyFailedWithTimeout(
                        client.AuthenticateAsClientAsync(clientOptions),
                        server.AuthenticateAsServerAsync(serverOptions));

                    // mutual authentication should only be set if server required client cert
                    Assert.Equal(expectMutualAuthentication, server.IsMutuallyAuthenticated);
                    Assert.Equal(expectMutualAuthentication, client.IsMutuallyAuthenticated);
                }
                ;
            }
        }

        [ConditionalTheory(typeof(TestConfiguration), nameof(TestConfiguration.SupportsRenegotiation))]
        [MemberData(nameof(CertSourceData))]
        [PlatformSpecific(TestPlatforms.Windows | TestPlatforms.Linux)]
        public async Task SslStream_NegotiateClientCertificate_IsMutuallyAuthenticatedCorrect(ClientCertSource certSource)
        {
            SslStreamCertificateContext context = SslStreamCertificateContext.Create(_serverCertificate, null);
            var clientOptions = new SslClientAuthenticationOptions
            {
                TargetHost = Guid.NewGuid().ToString("N")
            };

            for (int round = 0; round < 3; round++)
            {
                (Stream stream1, Stream stream2) = TestHelper.GetConnectedStreams();
                using (var client = new SslStream(stream1, false, AllowAnyCertificate))
                using (var server = new SslStream(stream2, false, AllowAnyCertificate))
                {

                    switch (certSource)
                    {
                        case ClientCertSource.ClientCertificate:
                            clientOptions.ClientCertificates = new X509CertificateCollection() { _clientCertificate };
                            break;
                        case ClientCertSource.SelectionCallback:
                            clientOptions.LocalCertificateSelectionCallback = ClientCertSelectionCallback;
                            break;
                        case ClientCertSource.CertificateContext:
                            clientOptions.ClientCertificateContext = SslStreamCertificateContext.Create(_clientCertificate, new());
                            break;
                    }

                    Task t2 = client.AuthenticateAsClientAsync(clientOptions);
                    Task t1 = server.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                    {
                        ServerCertificateContext = context,
                        ClientCertificateRequired = false,
                        EnabledSslProtocols = SslProtocols.Tls12,

                    });

                    await TestConfiguration.WhenAllOrAnyFailedWithTimeout(t1, t2);

                    if (round >= 0 && server.RemoteCertificate != null)
                    {
                        // TLS resumed
                        Assert.True(client.IsMutuallyAuthenticated, "client.IsMutuallyAuthenticated");
                        Assert.True(server.IsMutuallyAuthenticated, "server.IsMutuallyAuthenticated");
                        continue;
                    }

                    Assert.False(client.IsMutuallyAuthenticated, "client.IsMutuallyAuthenticated");
                    Assert.False(server.IsMutuallyAuthenticated, "server.IsMutuallyAuthenticated");

                    var t = client.ReadAsync(new byte[1]);
                    await server.NegotiateClientCertificateAsync();
                    Assert.NotNull(server.RemoteCertificate);
                    await server.WriteAsync(new byte[1]);
                    await t;

                    Assert.NotNull(server.RemoteCertificate);
                    Assert.True(client.IsMutuallyAuthenticated, "client.IsMutuallyAuthenticated");
                    Assert.True(server.IsMutuallyAuthenticated, "server.IsMutuallyAuthenticated");
                }
            }
        }

        [Theory]
        [ClassData(typeof(SslProtocolSupport.SupportedSslProtocolsTestData))]
        public async Task SslStream_ResumedSessionsClientCollection_IsMutuallyAuthenticatedCorrect(
           SslProtocols protocol)
        {
            var clientOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = protocol,
                RemoteCertificateValidationCallback = delegate { return true; },
                TargetHost = Guid.NewGuid().ToString("N")
            };

            // Create options with certificate context so TLS resume is possible on Linux
            var serverOptions = new SslServerAuthenticationOptions
            {
                ClientCertificateRequired = true,
                ServerCertificateContext = SslStreamCertificateContext.Create(_serverCertificate, null),
                RemoteCertificateValidationCallback = delegate { return true; },
                EnabledSslProtocols = protocol
            };

            for (int i = 0; i < 5; i++)
            {
                (SslStream client, SslStream server) = TestHelper.GetConnectedSslStreams();
                using (client)
                using (server)
                {
                    bool expectMutualAuthentication = (i % 2) == 0;

                    clientOptions.ClientCertificates = expectMutualAuthentication ? new X509CertificateCollection() { _clientCertificate } : null;
                    await TestConfiguration.WhenAllOrAnyFailedWithTimeout(
                        client.AuthenticateAsClientAsync(clientOptions),
                        server.AuthenticateAsServerAsync(serverOptions));

                    // mutual authentication should only be set if client set certificate
                    Assert.Equal(expectMutualAuthentication, server.IsMutuallyAuthenticated);
                    Assert.Equal(expectMutualAuthentication, client.IsMutuallyAuthenticated);

                    if (expectMutualAuthentication)
                    {
                        Assert.NotNull(server.RemoteCertificate);
                    }
                    else
                    {
                        Assert.Null(server.RemoteCertificate);
                    }
                }
                ;
            }
        }

        [Theory]
        [ClassData(typeof(SslProtocolSupport.SupportedSslProtocolsTestData))]
        public async Task SslStream_ResumedSessionsCallbackSet_IsMutuallyAuthenticatedCorrect(
           SslProtocols protocol)
        {
            var clientOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = protocol,
                RemoteCertificateValidationCallback = delegate { return true; },
                TargetHost = Guid.NewGuid().ToString("N")
            };

            // Create options with certificate context so TLS resume is possible on Linux
            var serverOptions = new SslServerAuthenticationOptions
            {
                ClientCertificateRequired = true,
                ServerCertificateContext = SslStreamCertificateContext.Create(_serverCertificate, null),
                RemoteCertificateValidationCallback = delegate { return true; },
                EnabledSslProtocols = protocol
            };

            for (int i = 0; i < 5; i++)
            {
                (SslStream client, SslStream server) = TestHelper.GetConnectedSslStreams();
                using (client)
                using (server)
                {
                    bool expectMutualAuthentication = (i % 2) == 0;

                    clientOptions.LocalCertificateSelectionCallback = (s, t, l, r, a) =>
                    {
                        return expectMutualAuthentication ? _clientCertificate : null;
                    };

                    await TestConfiguration.WhenAllOrAnyFailedWithTimeout(
                        client.AuthenticateAsClientAsync(clientOptions),
                        server.AuthenticateAsServerAsync(serverOptions));

                    // mutual authentication should only be set if client set certificate
                    Assert.Equal(expectMutualAuthentication, server.IsMutuallyAuthenticated);
                    Assert.Equal(expectMutualAuthentication, client.IsMutuallyAuthenticated);

                    if (expectMutualAuthentication)
                    {
                        Assert.NotNull(server.RemoteCertificate);
                    }
                    else
                    {
                        Assert.Null(server.RemoteCertificate);
                    }
                }
                ;
            }
        }

        [Theory]
        [ClassData(typeof(SslProtocolSupport.SupportedSslProtocolsTestData))]
        public async Task SslStream_ResumedSessionsCallbackMaybeSet_IsMutuallyAuthenticatedCorrect(
           SslProtocols protocol)
        {
            var clientOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = protocol,
                RemoteCertificateValidationCallback = delegate { return true; },
                TargetHost = Guid.NewGuid().ToString("N")
            };

            // Create options with certificate context so TLS resume is possible on Linux
            var serverOptions = new SslServerAuthenticationOptions
            {
                ClientCertificateRequired = true,
                ServerCertificateContext = SslStreamCertificateContext.Create(_serverCertificate, null),
                RemoteCertificateValidationCallback = delegate { return true; },
                EnabledSslProtocols = protocol
            };

            for (int i = 0; i < 5; i++)
            {
                (SslStream client, SslStream server) = TestHelper.GetConnectedSslStreams();
                using (client)
                using (server)
                {
                    bool expectMutualAuthentication = (i % 2) == 0;

                    if (expectMutualAuthentication)
                    {
                        clientOptions.LocalCertificateSelectionCallback = (s, t, l, r, a) => _clientCertificate;
                    }
                    else
                    {
                        clientOptions.LocalCertificateSelectionCallback = null;
                    }

                    await TestConfiguration.WhenAllOrAnyFailedWithTimeout(
                        client.AuthenticateAsClientAsync(clientOptions),
                        server.AuthenticateAsServerAsync(serverOptions));

                    // mutual authentication should only be set if client set certificate
                    Assert.Equal(expectMutualAuthentication, server.IsMutuallyAuthenticated);
                    Assert.Equal(expectMutualAuthentication, client.IsMutuallyAuthenticated);

                    if (expectMutualAuthentication)
                    {
                        Assert.NotNull(server.RemoteCertificate);
                    }
                    else
                    {
                        Assert.Null(server.RemoteCertificate);
                    }
                }
                ;
            }
        }

        [Theory]
        [ClassData(typeof(SslProtocolSupport.SupportedSslProtocolsTestData))]
        public async Task SslStream_Tls13ResumptionWithClientCert_IsMutuallyAuthenticatedTrue(
            SslProtocols protocol)
        {
            string targetHost = Guid.NewGuid().ToString("N");

            var clientOptions = new SslClientAuthenticationOptions
            {
                TargetHost = targetHost,
                ClientCertificates = new X509CertificateCollection { _clientCertificate },
                EnabledSslProtocols = protocol,
                RemoteCertificateValidationCallback = AllowAnyCertificate,
            };

            var serverOptions = new SslServerAuthenticationOptions
            {
                ServerCertificate = _serverCertificate,
                ClientCertificateRequired = true,
                EnabledSslProtocols = protocol,
                RemoteCertificateValidationCallback = AllowAnyCertificate,
            };

            for (int i = 0; i < 3; i++)
            {
                (SslStream client, SslStream server) = TestHelper.GetConnectedSslStreams();
                using (client)
                using (server)
                {
                    await TestConfiguration.WhenAllOrAnyFailedWithTimeout(
                        client.AuthenticateAsClientAsync(clientOptions),
                        server.AuthenticateAsServerAsync(serverOptions));

                    // PingPong triggers new session ticket delivery (TLS 1.3)
                    await TestHelper.PingPong(client, server);

                    // Regression test: all connections (including resumed ones) must report mutual auth
                    Assert.True(client.IsMutuallyAuthenticated, $"Client connection {i}: IsMutuallyAuthenticated should be true");
                    Assert.True(server.IsMutuallyAuthenticated, $"Server connection {i}: IsMutuallyAuthenticated should be true");
                    Assert.NotNull(client.LocalCertificate);
                    Assert.NotNull(server.RemoteCertificate);

                    await client.ShutdownAsync();
                    await server.ShutdownAsync();
                }
            }
        }

        private static bool AllowAnyCertificate(
            object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }

        private X509Certificate ClientCertSelectionCallback(
            object sender,
            string targetHost,
            X509CertificateCollection localCertificates,
            X509Certificate remoteCertificate,
            string[] acceptableIssuers)
        {
            return _clientCertificate;
        }
    }
}
