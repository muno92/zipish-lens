using System.Numerics;

namespace ZipishLens.Signature.Resource;

public record SignerInfo(
    BigInteger Version,
    IssuerAndSerialNumber? IssuerAndSerialNumber,
    byte[]? SubjectKeyIdentifier,
    string DigestAlgorithmIdentifier,
    SignedAttributes SignedAttributes
);
