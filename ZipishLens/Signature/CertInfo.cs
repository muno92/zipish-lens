using System.Numerics;

namespace ZipishLens.Signature;

public record CertInfo(
    BigInteger Version,
    BigInteger SerialNumber,
    string SignatureIdentifier,
    RelativeDistinguishedName Issuer,
    Validity Validity,
    RelativeDistinguishedName Subject
);
