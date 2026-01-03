namespace ZipishLens.Signature;

public record Certificate(
    CertInfo CertInfo
)
{
    public bool IsIntermediate(IReadOnlyList<Certificate> chain) =>
        chain.Any(c => c.CertInfo.Issuer.CommonName == CertInfo.Subject.CommonName);
}
