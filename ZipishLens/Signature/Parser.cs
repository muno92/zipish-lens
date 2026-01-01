using System.Formats.Asn1;

namespace ZipishLens.Signature;

public class Parser
{
    public static SignedData Parse(ReadOnlyMemory<byte> signature)
    {
        var reader = new AsnReader(signature, AsnEncodingRules.DER);
        try
        {
            var sequenceReader = reader.ReadSequence();
        }
        catch (AsnContentException e)
        {
            throw new InvalidDataException("Invalid signature format", e);
        }


        return new SignedData();
    }
}
