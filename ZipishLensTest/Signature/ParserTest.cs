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

        Assert.That(signature.Certificates, Is.EquivalentTo([
            new Certificate(new CertInfo(
                2,
                "1.2.840.113549.1.1.11",
                new RelativeDistinguishedName(
                    CommonName: "Apple Worldwide Developer Relations Certification Authority",
                    OrganizationalUnitName: "G4",
                    OrganizationName: "Apple Inc.",
                    CountryName: "US"
                )
            )),
            new Certificate(new CertInfo(
                2,
                "1.2.840.113549.1.1.11",
                new RelativeDistinguishedName(
                    CommonName: "Apple Root CA",
                    OrganizationalUnitName: "Apple Certification Authority",
                    OrganizationName: "Apple Inc.",
                    CountryName: "US"
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
