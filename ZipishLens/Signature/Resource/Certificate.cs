namespace ZipishLens.Signature.Resource;

public record Certificate(
    CertInfo CertInfo
)
{
    public bool IsIntermediate(IReadOnlyList<Certificate> chain) =>
        chain.Any(c => c.CertInfo.Issuer.CommonName == CertInfo.Subject.CommonName);
}
