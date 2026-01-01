using System.Numerics;

namespace ZipishLens.Signature;

public record CertInfo(
    BigInteger Version,
    // Skip Serial Number
    string SignatureIdentifier,
    RelativeDistinguishedName Issuer,
    Validity Validity
);
