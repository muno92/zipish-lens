using System.Numerics;
using NUnit.Framework;
using ZipishLens.Signature;

namespace ZipishLensTest.Signature;

public class ParserTest
{
    [Test]
    public void TestParseSignatureVersion()
    {
        var signature = ParseFixture("signature");

        Assert.That(signature.Version, Is.EqualTo((BigInteger)1));
    }

    [Test]
    public void TestParseSignatureDigestAlgorithm()
    {
        var signature = ParseFixture("signature");

        Assert.That(signature.DigestAlgorithmIdentifiers, Is.EqualTo("2.16.840.1.101.3.4.2.1"));
    }

    [Test]
    public void TestParseSignatureCertificates()
    {
        var signature = ParseFixture("signature");

        var maskedCertificates = signature.Certificates.Select((cert, index) =>
        {
            if (index == 0)
            {
                var maskedSubject = cert.CertInfo.Subject with
                {
                    OrganizationalUnitName = "Team Identifier",
                    OrganizationName = "Developer Name"
                };
                return new Certificate(cert.CertInfo with { Subject = maskedSubject });
            }

            return cert;
        }).ToList();

        Assert.That(maskedCertificates, Is.EquivalentTo([
            new Certificate(new CertInfo(
                2,
                "1.2.840.113549.1.1.11",
                new RelativeDistinguishedName(
                    CommonName: "Apple Worldwide Developer Relations Certification Authority",
                    OrganizationalUnitName: "G4",
                    OrganizationName: "Apple Inc.",
                    CountryName: "US",
                    UserId: null
                ),
                new Validity(
                    NotBefore: new DateTime(2025, 11, 17, 13, 21, 26, DateTimeKind.Utc),
                    NotAfter: new DateTime(2026, 12, 17, 13, 21, 25, DateTimeKind.Utc)
                ),
                new RelativeDistinguishedName(
                    CommonName: "Pass Type ID: pass.com.example.muno92",
                    OrganizationalUnitName: "Team Identifier",
                    OrganizationName: "Developer Name",
                    CountryName: "JP",
                    UserId: "pass.com.example.muno92"
                )
            )),
            new Certificate(new CertInfo(
                2,
                "1.2.840.113549.1.1.11",
                new RelativeDistinguishedName(
                    CommonName: "Apple Root CA",
                    OrganizationalUnitName: "Apple Certification Authority",
                    OrganizationName: "Apple Inc.",
                    CountryName: "US",
                    UserId: null
                ),
                new Validity(
                    NotBefore: new DateTime(2020, 12, 16, 19, 36, 04, DateTimeKind.Utc),
                    NotAfter: new DateTime(2030, 12, 10, 00, 00, 00, DateTimeKind.Utc)
                ),
                new RelativeDistinguishedName(
                    CommonName: "Apple Worldwide Developer Relations Certification Authority",
                    OrganizationalUnitName: "G4",
                    OrganizationName: "Apple Inc.",
                    CountryName: "US",
                    UserId: null
                )
            )),
        ]));
    }

    [TestCase("dummy.txt")]
    [TestCase("signature.pem")]
    [TestCase("digested_text.der")]
    [Test]
    public void TestParseInvalidSignature(string filename)
    {
        Assert.Throws<InvalidDataException>(() => { ParseFixture(filename); });
    }

    private static SignedData ParseFixture(string filename)
    {
        return Parser.Parse(File.ReadAllBytes($"Fixtures/{filename}").AsMemory());
    }
}
