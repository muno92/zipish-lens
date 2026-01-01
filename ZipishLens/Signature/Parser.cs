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
        var tbsCertificate = reader.ReadSequence();

        var version = tbsCertificate.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0)).ReadInteger();
        // Skip serialNumber
        tbsCertificate.ReadInteger();
        var signatureIdentifier = tbsCertificate.ReadSequence().ReadObjectIdentifier();
        var issuer = ParseName(tbsCertificate.ReadSequence());
        var validity = ParseValidity(tbsCertificate.ReadSequence());

        return new Certificate(new CertInfo(
            version,
            signatureIdentifier,
            issuer,
            validity
        ));
    }

    private static RelativeDistinguishedName ParseName(AsnReader reader)
    {
        var commonName = "";
        var organizationName = "";
        var organizationalUnitName = "";
        var countryName = "";

        while (reader.HasData)
        {
            var attribute = reader.ReadSetOf().ReadSequence();
            switch (attribute.ReadObjectIdentifier())
            {
                // countryName (C)
                case "2.5.4.6":
                    countryName = ReadString(attribute);
                    break;
                // commonName (CN)
                case "2.5.4.3":
                    commonName = ReadString(attribute);
                    break;
                // organizationName (O)
                case "2.5.4.10":
                    organizationName = ReadString(attribute);
                    break;
                // organizationalUnitName (OU)
                case "2.5.4.11":
                    organizationalUnitName = ReadString(attribute);
                    break;
            }
        }

        return new RelativeDistinguishedName(
            CommonName: commonName,
            OrganizationalUnitName: organizationalUnitName,
            OrganizationName: organizationName,
            CountryName: countryName
        );
    }

    private static Validity ParseValidity(AsnReader validitySequence)
    {
        var notBefore = validitySequence.ReadUtcTime();
        var notAfter = validitySequence.ReadUtcTime();

        return new Validity(
            NotBefore: notBefore.DateTime,
            NotAfter: notAfter.DateTime
        );
    }

    private static string ReadString(AsnReader stringSequence)
    {
        return stringSequence.PeekTag().TagValue switch
        {
            (int)UniversalTagNumber.PrintableString => stringSequence.ReadCharacterString(UniversalTagNumber
                .PrintableString),
            (int)UniversalTagNumber.UTF8String => stringSequence.ReadCharacterString(UniversalTagNumber.UTF8String),
            _ => "",
        };
    }
}
