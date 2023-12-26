using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Azure.Security.KeyVault.Certificates;
using Microsoft.Identity.Client;
using System;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Identity;
using Crypto = System.Security.Cryptography;

namespace OpenVsixSignTool.Core
{
    internal static class KeyVaultConfigurationDiscoverer
    {
        public static async Task<AzureKeyVaultMaterializedConfiguration> Materialize(AzureKeyVaultSignConfigurationSet configuration)
        {
            using (var httpClient = new HttpClient())
            {
                CertificateClientOptions certOptions = new CertificateClientOptions
                {
                    Transport = new HttpClientTransport(httpClient)
                };
                TokenCredential credential = configuration.Validate()
                    ? new ClientSecretCredential(configuration.AzureTenantId, configuration.AzureClientId,
                        configuration.AzureClientSecret) as TokenCredential
                    : new EnvironmentCredential();

                var certVault = new CertificateClient(new Uri(configuration.AzureKeyVaultUrl)
                    , credential
                    , certOptions);
                var azureCertificate = await certVault.GetCertificateAsync(configuration.AzureKeyVaultCertificateName);
                var x509Certificate = new X509Certificate2(azureCertificate.Value.Cer);
                var keyId = azureCertificate.Value.KeyId;
                var cryptoVault = new CryptographyClient(keyId, credential);
                return new AzureKeyVaultMaterializedConfiguration(cryptoVault, x509Certificate,
                    configuration.FileDigestAlgorithm, configuration.PkcsDigestAlgorithm);
            }
        }
    }

    public class AzureKeyVaultMaterializedConfiguration : IDisposable
    {
        public AzureKeyVaultMaterializedConfiguration(CryptographyClient client, X509Certificate2 publicCertificate,
            Crypto.HashAlgorithmName fileDigestAlgorithm, Crypto.HashAlgorithmName pkcsDigestAlgorithm)
        {
            Client = client;
            PublicCertificate = publicCertificate;
            FileDigestAlgorithm = fileDigestAlgorithm;
            PkcsDigestAlgorithm = pkcsDigestAlgorithm;
        }

        public Crypto.HashAlgorithmName FileDigestAlgorithm { get; }
        public Crypto.HashAlgorithmName PkcsDigestAlgorithm { get; }

        public X509Certificate2 PublicCertificate { get; }
        public CryptographyClient Client { get; }
        //public Uri KeyId { get; }

        public void Dispose()
        { }
    }
}
