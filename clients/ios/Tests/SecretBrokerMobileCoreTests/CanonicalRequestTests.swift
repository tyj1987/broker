import Foundation
import Testing
@testable import SecretBrokerMobileCore

@Test func canonicalEmptyBodyMatchesServerProtocol() {
    let message = BrokerCanonicalRequest.message(
        deviceID: "device-1",
        timestamp: 1_900_000_000_000,
        nonce: "nonce-1",
        method: "get",
        path: "/api/v2/devices/device-1/otp-tasks",
        body: Data()
    )
    #expect(String(decoding: message, as: UTF8.self) == [
        "secret-broker-device-request-v1",
        "device-1",
        "1900000000000",
        "nonce-1",
        "GET",
        "/api/v2/devices/device-1/otp-tasks",
        "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
    ].joined(separator: "\n"))
}

@Test func enrollmentMessageMatchesServerProtocol() {
    let value = BrokerCanonicalRequest.enrollmentMessage(
        enrollmentID: "11111111-1111-4111-8111-111111111111",
        challenge: "challenge"
    )
    #expect(String(decoding: value, as: UTF8.self) ==
        "secret-broker-device-enrollment-v1\n11111111-1111-4111-8111-111111111111\nchallenge")
}

@Test func endpointRejectsUserInfoAndPaths() {
    #expect(throws: BrokerClientError.self) { try BrokerDeviceClient(endpoint: "http://broker.example.com") }
    #expect(throws: BrokerClientError.self) { try BrokerDeviceClient(endpoint: "https://user@broker.example.com") }
    #expect(throws: BrokerClientError.self) { try BrokerDeviceClient(endpoint: "https://broker.example.com/path") }
}
