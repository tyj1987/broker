import Foundation

public struct BrokerDevice: Codable, Sendable {
    public let id: String
    public let label: String
    public let platform: String
    public let signatureAlgorithm: String
    public let state: String

    enum CodingKeys: String, CodingKey {
        case id, label, platform, state
        case signatureAlgorithm = "signature_algorithm"
    }
}

public enum BrokerClientError: Error, Equatable {
    case invalidEndpoint
    case insecureEndpoint
    case invalidInput
    case redirectDenied
    case transport
    case server(status: Int, code: String)
    case invalidResponse
}

private final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

public final class BrokerDeviceClient: Sendable {
    private let origin: URL
    private let session: URLSession
    private let signer: SecureEnclaveDeviceSigner

    public init(endpoint: String, signer: SecureEnclaveDeviceSigner = .init()) throws {
        guard let url = URL(string: endpoint), url.scheme == "https", url.user == nil,
              url.password == nil, url.query == nil, url.fragment == nil,
              url.path.isEmpty || url.path == "/" else {
            throw BrokerClientError.invalidEndpoint
        }
        guard url.host != nil else { throw BrokerClientError.invalidEndpoint }
        self.origin = url
        self.signer = signer
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        configuration.timeoutIntervalForRequest = 10
        configuration.timeoutIntervalForResource = 15
        self.session = URLSession(configuration: configuration, delegate: NoRedirectDelegate(), delegateQueue: nil)
    }

    public func finishEnrollment(enrollmentID: String, challenge: String) async throws -> BrokerDevice {
        guard UUID(uuidString: enrollmentID) != nil,
              challenge.range(of: "^[A-Za-z0-9_-]{32,128}$", options: .regularExpression) != nil else {
            throw BrokerClientError.invalidInput
        }
        let message = BrokerCanonicalRequest.enrollmentMessage(enrollmentID: enrollmentID, challenge: challenge)
        let payload = [
            "enrollment_id": enrollmentID,
            "signature_algorithm": SecureEnclaveDeviceSigner.signatureAlgorithm,
            "public_key_pem": try signer.publicKeyPEM(),
            "signature": try signer.sign(message),
        ]
        let body = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
        let data = try await request(path: "/api/v2/devices/enroll/finish", method: "POST", body: body)
        guard let device = try? JSONDecoder().decode(BrokerDevice.self, from: data) else {
            throw BrokerClientError.invalidResponse
        }
        return device
    }

    private func request(path: String, method: String, body: Data) async throws -> Data {
        guard let url = URL(string: path, relativeTo: origin), url.host == origin.host,
              url.scheme == origin.scheme, url.port == origin.port else {
            throw BrokerClientError.invalidEndpoint
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw BrokerClientError.transport
        }
        guard let http = response as? HTTPURLResponse else { throw BrokerClientError.invalidResponse }
        guard (200..<300).contains(http.statusCode) else {
            let code = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["error"] as? String
                ?? "request_failed"
            throw BrokerClientError.server(status: http.statusCode, code: code)
        }
        guard data.count <= 64 * 1024 else { throw BrokerClientError.invalidResponse }
        return data
    }
}
