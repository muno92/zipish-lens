using System.Numerics;

namespace ZipishLens.Signature.Resource;

public record IssuerAndSerialNumber(
    RelativeDistinguishedName Issuer,
    BigInteger SerialNumber
);
