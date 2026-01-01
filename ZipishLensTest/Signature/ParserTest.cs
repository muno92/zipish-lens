using NUnit.Framework;
using ZipishLens.Signature;

namespace ZipishLensTest.Signature;

public class ParserTest
{
    [Test]
    public void TestParseSignature()
    {
        var signature = Parser.Parse(File.ReadAllBytes("Fixtures/signature").AsMemory());

        Assert.That(signature, Is.Not.Null);
    }

    [TestCase("dummy.txt")]
    [Test]
    public void TestParseInvalidSignature(string filename)
    {
        Assert.Throws<InvalidDataException>(() =>
        {
            var signature = Parser.Parse(File.ReadAllBytes($"Fixtures/{filename}").AsMemory());
        });
    }
}
