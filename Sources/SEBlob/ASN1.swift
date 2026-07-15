import Foundation

public enum ASN1 {
    /// DER encoding of OID 1.2.840.10045.3.1.7 (secp256r1 / prime256v1).
    public static let secp256r1OID = Data([0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])

    /// Wraps an uncompressed EC point in a DER OCTET STRING for CKA_EC_POINT.
    public static func wrapOctetString(_ content: Data) -> Data {
        var out = Data([0x04])
        out.append(contentsOf: encodeLength(content.count))
        out.append(content)
        return out
    }

    private static func encodeLength(_ length: Int) -> [UInt8] {
        if length < 0x80 { return [UInt8(length)] }
        var bytes: [UInt8] = []
        var value = length
        while value > 0 {
            bytes.insert(UInt8(value & 0xFF), at: 0)
            value >>= 8
        }
        return [UInt8(0x80 | bytes.count)] + bytes
    }
}
