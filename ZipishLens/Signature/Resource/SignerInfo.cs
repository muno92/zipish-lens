using System.Numerics;

namespace ZipishLens.Signature.Resource;

public record SignerInfo(
    BigInteger Version,
    IssuerAndSerialNumber? IssuerAndSerialNumber,
    string DigestAlgorithmIdentifier
);
