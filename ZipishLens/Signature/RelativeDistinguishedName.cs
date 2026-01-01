namespace ZipishLens.Signature;

public record RelativeDistinguishedName(
    string CommonName,
    string OrganizationalUnitName,
    string OrganizationName,
    string CountryName
);
