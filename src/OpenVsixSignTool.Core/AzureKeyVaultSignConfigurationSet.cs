﻿using Crypto = System.Security.Cryptography;

namespace OpenVsixSignTool.Core
{
    public sealed class AzureKeyVaultSignConfigurationSet
    {
        public string AzureTenantId { get; set; }
        public string AzureClientId { get; set; }
        public string AzureClientSecret { get; set; }
        public string AzureKeyVaultUrl { get; set; }
        public string AzureKeyVaultCertificateName { get; set; }

        public Crypto.HashAlgorithmName FileDigestAlgorithm { get; set; }
        public Crypto.HashAlgorithmName PkcsDigestAlgorithm { get; set; }

        public bool Validate()
        {
            // Logging candidate.
            if (string.IsNullOrWhiteSpace(AzureTenantId))
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(AzureClientId))
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(AzureClientSecret))
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(AzureKeyVaultUrl))
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(AzureKeyVaultCertificateName))
            {
                return false;
            }

            return true;
        }
    }
}