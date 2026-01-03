using System.Numerics;

namespace ZipishLens.Signature.Resource;

public record SignedData(
    BigInteger Version,
    string DigestAlgorithmIdentifiers,
    IReadOnlyList<Certificate> Certificates,
    IReadOnlyList<SignerInfo> SignerInfos
)
{
    /// <summary>
    /// Returns the certificate that signed the signature.
    /// </summary>
    public Certificate IssuerCertificate
    {
        get
        {
            // SignerInfo is defined as a collection in the RFC, but Apple Wallet should only have one.
            var signerInfo = SignerInfos.Single();

            return Certificates.Single(c => c.CertInfo.SerialNumber == signerInfo.IssuerAndSerialNumber?.SerialNumber);
        }
    }

    /// <summary>
    /// Returns the intermediate certificate if it exists (some signatures don't include it).
    /// </summary>
    public Certificate? IntermediateCertificate
    {
        get
        {
            var issuerNames = Certificates.Select(c => c.CertInfo.Issuer.CommonName);

            return Certificates.SingleOrDefault(c => issuerNames.Contains(c.CertInfo.Subject.CommonName));
        }
    }
}
