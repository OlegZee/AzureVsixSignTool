using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Packaging;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Xml;
using Azure.Security.KeyVault.Certificates;
using Xunit;

namespace OpenVsixSignTool.Core.Tests
{
    public class OpcPackageSigningTests : IDisposable
    {
        private readonly string SamplePackage = @"sample" + Path.DirectorySeparatorChar + "OpenVsixSignToolTest.vsix";
        private readonly string SamplePackageSigned = @"sample" + Path.DirectorySeparatorChar + "OpenVsixSignToolTest-Signed.vsix";
        private readonly List<string> _shadowFiles = new List<string>();

        private static readonly string certsPathPrefix = "certs" + Path.DirectorySeparatorChar;


        [Theory]
        [MemberData(nameof(RsaSigningTheories))]
        public async Task ShouldSignFileWithRsa(string pfxPath, HashAlgorithmName fileDigestAlgorithm, string expectedAlgorithm)
        {
            string path;
            using (var package = ShadowCopyPackage(SamplePackage, out path, OpcPackageFileMode.ReadWrite))
            {
                var builder = package.CreateSignatureBuilder();
                builder.EnqueueNamedPreset<VSIXSignatureBuilderPreset>();
                var result = await builder.SignAsync(
                    new CertificateSignConfigurationSet
                    {
                        FileDigestAlgorithm = fileDigestAlgorithm,
                        PkcsDigestAlgorithm = fileDigestAlgorithm,
                        SigningCertificate = new X509Certificate2(pfxPath, "test")
                    }
                );
                Assert.NotNull(result);
            }
        }

        [Theory]
        [MemberData(nameof(EcdsaSigningTheories))]
        public async Task ShouldSignFileWithEcdsa(string pfxPath, HashAlgorithmName fileDigestAlgorithm, string expectedAlgorithm)
        {
            using (var package = ShadowCopyPackage(SamplePackage, out _, OpcPackageFileMode.ReadWrite))
            {
                var builder = package.CreateSignatureBuilder();
                builder.EnqueueNamedPreset<VSIXSignatureBuilderPreset>();
                await builder.SignAsync(
                    new CertificateSignConfigurationSet
                    {
                        FileDigestAlgorithm = fileDigestAlgorithm,
                        PkcsDigestAlgorithm = fileDigestAlgorithm,
                        SigningCertificate = new X509Certificate2(pfxPath, "test")
                    }
                );
            }
        }

        public static IEnumerable<object[]> RsaSigningTheories
        {
            get
            {
                yield return new object[] { certsPathPrefix + "rsa-2048-sha256.pfx", HashAlgorithmName.SHA512, OpcKnownUris.SignatureAlgorithms.rsaSHA512.AbsoluteUri };
                yield return new object[] { certsPathPrefix + "rsa-2048-sha256.pfx", HashAlgorithmName.SHA384, OpcKnownUris.SignatureAlgorithms.rsaSHA384.AbsoluteUri };
                yield return new object[] { certsPathPrefix + "rsa-2048-sha256.pfx", HashAlgorithmName.SHA256, OpcKnownUris.SignatureAlgorithms.rsaSHA256.AbsoluteUri };
                yield return new object[] { certsPathPrefix + "rsa-2048-sha256.pfx", HashAlgorithmName.SHA1, OpcKnownUris.SignatureAlgorithms.rsaSHA1.AbsoluteUri };
                yield return new object[] { certsPathPrefix + "rsa-2048-sha1.pfx", HashAlgorithmName.SHA512, OpcKnownUris.SignatureAlgorithms.rsaSHA512.AbsoluteUri };
                yield return new object[] { certsPathPrefix + "rsa-2048-sha1.pfx", HashAlgorithmName.SHA384, OpcKnownUris.SignatureAlgorithms.rsaSHA384.AbsoluteUri };
                yield return new object[] { certsPathPrefix + "rsa-2048-sha1.pfx", HashAlgorithmName.SHA256, OpcKnownUris.SignatureAlgorithms.rsaSHA256.AbsoluteUri };
                yield return new object[] { certsPathPrefix + "rsa-2048-sha1.pfx", HashAlgorithmName.SHA1, OpcKnownUris.SignatureAlgorithms.rsaSHA1.AbsoluteUri };
            }
        }

        public static IEnumerable<object[]> EcdsaSigningTheories
        {
            get
            {
                yield return new object[] { certsPathPrefix + "ecdsa-p256-sha256.pfx", HashAlgorithmName.SHA256, OpcKnownUris.SignatureAlgorithms.ecdsaSHA256.AbsoluteUri };
                yield return new object[] { certsPathPrefix + "ecdsa-p256-sha256.pfx", HashAlgorithmName.SHA1, OpcKnownUris.SignatureAlgorithms.ecdsaSHA1.AbsoluteUri };
            }
        }

        [Theory]
        [MemberData(nameof(RsaTimestampTheories))]
        public async Task ShouldTimestampFileWithRsa(string pfxPath, HashAlgorithmName timestampDigestAlgorithm)
        {
            using (var package = ShadowCopyPackage(SamplePackage, out _, OpcPackageFileMode.ReadWrite))
            {
                var signerBuilder = package.CreateSignatureBuilder();
                signerBuilder.EnqueueNamedPreset<VSIXSignatureBuilderPreset>();
                var signature = await signerBuilder.SignAsync(
                    new CertificateSignConfigurationSet
                    {
                        FileDigestAlgorithm = HashAlgorithmName.SHA256,
                        PkcsDigestAlgorithm = HashAlgorithmName.SHA256,
                        SigningCertificate = new X509Certificate2(pfxPath, "test")
                    }
                );
                var timestampBuilder = signature.CreateTimestampBuilder();
                var result = await timestampBuilder.SignAsync(new Uri("http://timestamp.digicert.com"), timestampDigestAlgorithm);
                Assert.Equal(TimestampResult.Success, result);
            }
        }

        [Fact]
        public async Task ShouldSupportReSigning()
        {
            string path;
            using (var package = ShadowCopyPackage(SamplePackage, out path, OpcPackageFileMode.ReadWrite))
            {
                var signerBuilder = package.CreateSignatureBuilder();
                signerBuilder.EnqueueNamedPreset<VSIXSignatureBuilderPreset>();
                await signerBuilder.SignAsync(
                    new CertificateSignConfigurationSet
                    {
                        PkcsDigestAlgorithm = HashAlgorithmName.SHA256,
                        FileDigestAlgorithm = HashAlgorithmName.SHA256,
                        SigningCertificate = new X509Certificate2(certsPathPrefix + "rsa-2048-sha256.pfx", "test")
                    }
                );
            }
            using (var package = OpcPackage.Open(path, OpcPackageFileMode.ReadWrite))
            {
                var signerBuilder = package.CreateSignatureBuilder();
                signerBuilder.EnqueueNamedPreset<VSIXSignatureBuilderPreset>();
                await signerBuilder.SignAsync(
                    new CertificateSignConfigurationSet
                    {
                        PkcsDigestAlgorithm = HashAlgorithmName.SHA256,
                        FileDigestAlgorithm = HashAlgorithmName.SHA256,
                        SigningCertificate = new X509Certificate2(certsPathPrefix + "rsa-2048-sha256.pfx", "test")
                    }
                );
            }
            using (var netfxPackage = Package.Open(path, FileMode.Open))
            {
                var signatureManager = new PackageDigitalSignatureManager(netfxPackage);
                Assert.Equal(VerifyResult.Success, signatureManager.VerifySignatures(true));
                if (signatureManager.Signatures.Count != 1 || signatureManager.Signatures[0].SignedParts.Count != netfxPackage.GetParts().Count() - 1)
                {
                    Assert.Fail("Missing parts");
                }
            }
        }

        [Fact]
        public async Task ShouldSupportReSigningWithDifferentCertificate()
        {
            string path;
            using (var package = ShadowCopyPackage(SamplePackage, out path, OpcPackageFileMode.ReadWrite))
            {
                var signerBuilder = package.CreateSignatureBuilder();
                signerBuilder.EnqueueNamedPreset<VSIXSignatureBuilderPreset>();
                await signerBuilder.SignAsync(
                    new CertificateSignConfigurationSet
                    {
                        PkcsDigestAlgorithm = HashAlgorithmName.SHA1,
                        FileDigestAlgorithm = HashAlgorithmName.SHA1,
                        SigningCertificate = new X509Certificate2(certsPathPrefix + "rsa-2048-sha1.pfx", "test")
                    }
                );
            }
            using (var package = OpcPackage.Open(path, OpcPackageFileMode.ReadWrite))
            {
                var signerBuilder = package.CreateSignatureBuilder();
                signerBuilder.EnqueueNamedPreset<VSIXSignatureBuilderPreset>();
                await signerBuilder.SignAsync(
                    new CertificateSignConfigurationSet
                    {
                        PkcsDigestAlgorithm = HashAlgorithmName.SHA256,
                        FileDigestAlgorithm = HashAlgorithmName.SHA256,
                        SigningCertificate = new X509Certificate2(certsPathPrefix + "rsa-2048-sha256.pfx", "test")
                    }
                );
            }
            using (var netfxPackage = Package.Open(path, FileMode.Open))
            {
                var signatureManager = new PackageDigitalSignatureManager(netfxPackage);
                Assert.Equal(VerifyResult.Success, signatureManager.VerifySignatures(true));
                if (signatureManager.Signatures.Count != 1 || signatureManager.Signatures[0].SignedParts.Count != netfxPackage.GetParts().Count() - 1)
                {
                    Assert.Fail("Missing parts");
                }
                var packageSignature = signatureManager.Signatures[0];
                Assert.Equal(OpcKnownUris.SignatureAlgorithms.rsaSHA256.AbsoluteUri, packageSignature.Signature.SignedInfo.SignatureMethod);
            }
        }

        [Fact]
        public async Task ShouldRemoveSignature()
        {
            string path;
            using (var package = ShadowCopyPackage(SamplePackage, out path, OpcPackageFileMode.ReadWrite))
            {
                var signerBuilder = package.CreateSignatureBuilder();
                signerBuilder.EnqueueNamedPreset<VSIXSignatureBuilderPreset>();
                await signerBuilder.SignAsync(
                    new CertificateSignConfigurationSet
                    {
                        FileDigestAlgorithm = HashAlgorithmName.SHA1,
                        PkcsDigestAlgorithm = HashAlgorithmName.SHA1,
                        SigningCertificate = new X509Certificate2(certsPathPrefix + "rsa-2048-sha1.pfx", "test")
                    }
                );
            }
            using (var package = OpcPackage.Open(path, OpcPackageFileMode.ReadWrite))
            {
                var signatures = package.GetSignatures().ToList();
                Assert.Single(signatures);
                var signature = signatures[0];
                signature.Remove();
                Assert.Null(signature.Part);
                Assert.Throws<InvalidOperationException>(() => signature.CreateTimestampBuilder());
                Assert.Empty(package.GetSignatures());
            }
        }

        public static IEnumerable<object[]> RsaTimestampTheories
        {
            get
            {
                yield return new object[] { certsPathPrefix + "rsa-2048-sha256.pfx", HashAlgorithmName.SHA256 };
                yield return new object[] { certsPathPrefix + "rsa-2048-sha256.pfx", HashAlgorithmName.SHA1 };
                yield return new object[] { certsPathPrefix + "rsa-2048-sha1.pfx", HashAlgorithmName.SHA256 };
                yield return new object[] { certsPathPrefix + "rsa-2048-sha1.pfx", HashAlgorithmName.SHA1 };
            }
        }

        private OpcPackage ShadowCopyPackage(string packagePath, out string path, OpcPackageFileMode mode = OpcPackageFileMode.Read)
        {
            var temp = Path.GetTempFileName();
            _shadowFiles.Add(temp);
            File.Copy(packagePath, temp, true);
            path = temp;
            return OpcPackage.Open(temp, mode);
        }

        public void Dispose()
        {
            void CleanUpShadows()
            {
                _shadowFiles.ForEach(File.Delete);
            }
            CleanUpShadows();
        }
    }
}
