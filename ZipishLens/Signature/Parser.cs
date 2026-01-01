using System.Formats.Asn1;

namespace ZipishLens.Signature;

public class Parser
{
    public static SignedData Parse(ReadOnlyMemory<byte> signature)
    {
        var reader = new AsnReader(signature, AsnEncodingRules.DER);

        return new SignedData();
    }
}
