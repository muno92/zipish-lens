namespace ZipishLens.Signature.Resource;

public record RelativeDistinguishedName(
    string CommonName,
    string OrganizationalUnitName,
    string OrganizationName,
    string CountryName,
    string? UserId
)
{
    public override string ToString()
    {
        var text = $"CN: {CommonName}, OU: {OrganizationalUnitName}, O: {OrganizationName}, C: {CountryName}";
        if (UserId is not null)
        {
            return $"UID: {UserId}, {text}";
        }

        return text;
    }
}
