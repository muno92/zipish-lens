using System.Numerics;

namespace ZipishLens.Signature.Resource;

public record SignedData(
    BigInteger Version,
    string DigestAlgorithmIdentifiers,
    IReadOnlyList<Certificate> Certificates
);
