import Foundation
import Security

public enum DeviceSignerError: Error, Equatable {
    case keychain(OSStatus)
    case secureEnclaveUnavailable
    case publicKeyUnavailable
    case invalidPublicKey
    case signingFailed
}

public final class SecureEnclaveDeviceSigner: @unchecked Sendable {
    public static let signatureAlgorithm = "p256-sha256"

    private let applicationTag: Data

    public init(applicationTag: String = "com.secretbroker.ios.device.v1") {
        self.applicationTag = Data(applicationTag.utf8)
    }

    public func loadOrCreatePrivateKey() throws -> SecKey {
        let query: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: applicationTag,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef: true,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess, let item { return item as! SecKey }
        guard status == errSecItemNotFound else { throw DeviceSignerError.keychain(status) }

        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            [.privateKeyUsage],
            &accessError
        ) else {
            throw DeviceSignerError.secureEnclaveUnavailable
        }
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: applicationTag,
                kSecAttrAccessControl: access,
            ],
        ]
        var creationError: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &creationError) else {
            throw DeviceSignerError.secureEnclaveUnavailable
        }
        return key
    }

    public func publicKeyPEM() throws -> String {
        let privateKey = try loadOrCreatePrivateKey()
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw DeviceSignerError.publicKeyUnavailable
        }
        var error: Unmanaged<CFError>?
        guard let representation = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw DeviceSignerError.publicKeyUnavailable
        }
        guard representation.count == 65, representation.first == 0x04 else {
            throw DeviceSignerError.invalidPublicKey
        }

        // SubjectPublicKeyInfo for id-ecPublicKey + prime256v1, followed by the
        // uncompressed ANSI X9.63 public point returned by Security.framework.
        let spkiPrefix: [UInt8] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
            0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
            0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ]
        let encoded = (Data(spkiPrefix) + representation).base64EncodedString()
        let lines = stride(from: 0, to: encoded.count, by: 64).map { offset in
            let start = encoded.index(encoded.startIndex, offsetBy: offset)
            let end = encoded.index(start, offsetBy: min(64, encoded.count - offset))
            return String(encoded[start..<end])
        }
        return (["-----BEGIN PUBLIC KEY-----"] + lines + ["-----END PUBLIC KEY-----", ""])
            .joined(separator: "\n")
    }

    public func sign(_ message: Data) throws -> String {
        let privateKey = try loadOrCreatePrivateKey()
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            message as CFData,
            &error
        ) as Data? else {
            throw DeviceSignerError.signingFailed
        }
        return signature.base64URLEncodedString()
    }
}
