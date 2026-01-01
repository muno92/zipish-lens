using NUnit.Framework;
using ZipishLens.Signature;

namespace ZipishLensTest.Signature;

public class ParserTest
{
    [Test]
    public void TestParseSignature()
    {
        var signature = Parser.Parse(File.ReadAllBytes("Fixtures/signature").AsMemory());

        Assert.That(signature, Is.EqualTo(new SignedData(
            1,
            "2.16.840.1.101.3.4.2.1"
        )));
    }

    [TestCase("dummy.txt")]
    [TestCase("signature.pem")]
    [TestCase("digested_text.der")]
    [Test]
    public void TestParseInvalidSignature(string filename)
    {
        Assert.Throws<InvalidDataException>(() =>
        {
            var signature = Parser.Parse(File.ReadAllBytes($"Fixtures/{filename}").AsMemory());
        });
    }
}
