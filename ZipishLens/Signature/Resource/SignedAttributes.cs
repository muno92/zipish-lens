namespace ZipishLens.Signature.Resource;

public record SignedAttributes(
    DateTime SigningTime,
    string? ContentType,
    string? MessageDigest
);
