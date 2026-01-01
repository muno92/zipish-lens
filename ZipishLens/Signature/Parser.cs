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
        var content = reader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        var signedData = content.ReadSequence();

        var version = signedData.ReadInteger();
        var digestAlgorithmIdentifiers = signedData.ReadSetOf().ReadSequence().ReadObjectIdentifier();
        // Skip encapContentInfo. (that is absent)
        signedData.ReadSequence();
        var certificates = EnumerateCertificates(signedData.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0)));

        return new SignedData(
            version,
            digestAlgorithmIdentifiers,
            certificates
        );
    }

    private static IReadOnlyList<Certificate> EnumerateCertificates(AsnReader reader)
    {
        var certificates = new List<Certificate>();

        while (reader.HasData)
        {
            certificates.Add(ParseCertificate(reader.ReadSequence()));
        }

        return certificates.AsReadOnly();
    }

    private static Certificate ParseCertificate(AsnReader reader)
    {
        return new Certificate();
    }
}
