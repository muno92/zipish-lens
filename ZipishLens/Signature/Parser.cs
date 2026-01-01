using System.Formats.Asn1;

namespace ZipishLens.Signature;

public class Parser
{
    private static readonly string OidPkcs7SignedData = "1.2.840.113549.1.7.2";

    public static SignedData Parse(ReadOnlyMemory<byte> signature)
    {
        var reader = new AsnReader(signature, AsnEncodingRules.DER);
        try
        {
            var contentInfo = reader.ReadSequence();
            var contentType = contentInfo.ReadObjectIdentifier();

            if (contentType != OidPkcs7SignedData)
            {
                throw new InvalidDataException("Not a PKCS#7 SignedData structure");
            }

            return ParseSignedDataContent(contentInfo);
        }
        catch (AsnContentException e)
        {
            throw new InvalidDataException("Invalid signature format", e);
        }
    }

    private static SignedData ParseSignedDataContent(AsnReader reader)
    {
        var contentTag = new Asn1Tag(TagClass.ContextSpecific, 0);
        var content = reader.ReadSequence(contentTag);
        var signedData = content.ReadSequence();

        var version = signedData.ReadInteger();

        return new SignedData(version);
    }
}
