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
            new Certificate(new CertInfo(2)),
            new Certificate(new CertInfo(2))
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
