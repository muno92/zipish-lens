using System.Numerics;

namespace ZipishLens.Signature;

public record SignedData(
    BigInteger Version,
    string DigestAlgorithmIdentifiers,
    IReadOnlyList<Certificate> Certificates
);
