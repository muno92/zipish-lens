using System.Formats.Asn1;
using ZipishLens.Signature.Resource;

namespace ZipishLens.Signature;

public class Parser
{
    private static readonly string OidPkcs7SignedData = "1.2.840.113549.1.7.2";

    public static SignedData Parse(ReadOnlyMemory<byte> signature)
    {
        var contentInfo = ParseSignature(signature);

        var contentType = contentInfo.ReadObjectIdentifier();
        if (contentType != OidPkcs7SignedData)
        {
            throw new InvalidDataException("Not a PKCS#7 SignedData structure");
        }

        return ParseSignedDataContent(contentInfo);
    }

    private static AsnReader ParseSignature(ReadOnlyMemory<byte> signature)
    {
        var derReader = new AsnReader(signature, AsnEncodingRules.DER);
        try
        {
            return derReader.ReadSequence();
        }
        catch (AsnContentException)
        {
            // Some signatures are BER encoded.
            var berReader = new AsnReader(signature, AsnEncodingRules.BER);
            try
            {
                return berReader.ReadSequence();
            }
            catch (AsnContentException e)
            {
                throw new InvalidDataException("Invalid signature format", e);
            }
        }
    }

    private static SignedData ParseSignedDataContent(AsnReader reader)
    {
        var content = reader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        var signedData = content.ReadSequence();

        var version = signedData.ReadInteger();
        var digestAlgorithmIdentifiers = signedData.ReadSetOf().ReadSequence().ReadObjectIdentifier();
        // Skip encapContentInfo. (that is absent when pass is detached.)
        signedData.ReadSequence();
        var certificates = EnumerateCertificates(signedData.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0)));
        var signerInfos = EnumerateSignerInfos(signedData.ReadSetOf());

        return new SignedData(
            version,
            digestAlgorithmIdentifiers,
            certificates,
            signerInfos
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
        var serialNumber = tbsCertificate.ReadInteger();
        var signatureIdentifier = tbsCertificate.ReadSequence().ReadObjectIdentifier();
        var issuer = ParseName(tbsCertificate.ReadSequence());
        var validity = ParseValidity(tbsCertificate.ReadSequence());
        var subject = ParseName(tbsCertificate.ReadSequence());

        return new Certificate(new CertInfo(
            version,
            serialNumber,
            signatureIdentifier,
            issuer,
            validity,
            subject
        ));
    }

    private static IReadOnlyList<SignerInfo> EnumerateSignerInfos(AsnReader reader)
    {
        var signerInfos = new List<SignerInfo>();

        while (reader.HasData)
        {
            signerInfos.Add(ParseSignerInfo(reader.ReadSequence()));
        }

        return signerInfos.AsReadOnly();
    }

    private static SignerInfo ParseSignerInfo(AsnReader reader)
    {
        var version = reader.ReadInteger();

        var issuerAndSerialNumber = null as IssuerAndSerialNumber;
        if (version == 1)
        {
            var issuerAndSerialNumberSequence = reader.ReadSequence();
            issuerAndSerialNumber = new IssuerAndSerialNumber(
                ParseName(issuerAndSerialNumberSequence.ReadSequence()),
                issuerAndSerialNumberSequence.ReadInteger()
            );
        }

        var digestAlgorithmIdentifier = reader.ReadSequence().ReadObjectIdentifier();
        var signedAttributes = ParseSignedAttributes(reader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0)));

        return new SignerInfo(
            version,
            issuerAndSerialNumber,
            digestAlgorithmIdentifier,
            signedAttributes
        );
    }

    private static SignedAttributes ParseSignedAttributes(AsnReader reader)
    {
        var contentType = "";
        // signingTime is required for Apple Wallet, so it's only default value.
        var signingTime = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var messageDigest = null as string;

        while (reader.HasData)
        {
            var attribute = reader.ReadSequence();
            switch (attribute.ReadObjectIdentifier())
            {
                // contentType
                case "1.2.840.113549.1.9.3":
                    contentType = attribute.ReadSetOf().ReadObjectIdentifier();
                    break;
                // signingTime
                case "1.2.840.113549.1.9.5":
                    signingTime = attribute.ReadSetOf().ReadUtcTime().DateTime;
                    break;
                // messageDigest
                case "1.2.840.113549.1.9.4":
                    messageDigest = Convert.ToHexString(attribute.ReadSetOf().ReadOctetString());
                    break;
            }
        }

        return new SignedAttributes(signingTime, contentType, messageDigest);
    }

    private static RelativeDistinguishedName ParseName(AsnReader reader)
    {
        var commonName = "";
        var organizationName = "";
        var organizationalUnitName = "";
        var countryName = "";
        var userId = null as string;

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
                // userId (uid)
                case "0.9.2342.19200300.100.1.1":
                    userId = ReadString(attribute);
                    break;
            }
        }

        return new RelativeDistinguishedName(
            CommonName: commonName,
            OrganizationalUnitName: organizationalUnitName,
            OrganizationName: organizationName,
            CountryName: countryName,
            UserId: userId
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
