import CryptoKit
import Foundation

public enum BrokerCanonicalRequest {
    public static func bodyHash(_ body: Data) -> String {
        Data(SHA256.hash(data: body)).base64URLEncodedString()
    }

    public static func message(
        deviceID: String,
        timestamp: Int64,
        nonce: String,
        method: String,
        path: String,
        body: Data
    ) -> Data {
        [
            "secret-broker-device-request-v1",
            deviceID,
            String(timestamp),
            nonce,
            method.uppercased(),
            path,
            bodyHash(body),
        ].joined(separator: "\n").data(using: .utf8)!
    }

    public static func enrollmentMessage(enrollmentID: String, challenge: String) -> Data {
        "secret-broker-device-enrollment-v1\n\(enrollmentID)\n\(challenge)"
            .data(using: .utf8)!
    }
}

extension Data {
    public func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
