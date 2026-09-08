import SecretBrokerMobileCore
import SwiftUI

@main
struct SecretBrokerIOSApp: App {
    var body: some Scene {
        WindowGroup { PairingView() }
    }
}

private struct PairingView: View {
    @AppStorage("broker-endpoint") private var endpoint = "https://broker.example.com"
    @AppStorage("broker-device-id") private var deviceID = ""
    @State private var enrollmentID = ""
    @State private var challenge = ""
    @State private var status = "Not paired"
    @State private var pairing = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Broker") {
                    TextField("HTTPS endpoint", text: $endpoint)
                    if !deviceID.isEmpty { LabeledContent("Device", value: String(deviceID.prefix(12)) + "…") }
                }
                Section("Short-lived pairing challenge") {
                    TextField("Enrollment UUID", text: $enrollmentID)
                    SecureField("Challenge", text: $challenge)
                    Button(pairing ? "Pairing…" : "Pair this device") {
                        Task { await pair() }
                    }
                    .disabled(pairing || !deviceID.isEmpty)
                }
                Section("Status") { Text(status) }
            }
            .navigationTitle("Secret Broker")
        }
    }

    @MainActor
    private func pair() async {
        pairing = true
        defer {
            challenge = ""
            pairing = false
        }
        do {
            let client = try BrokerDeviceClient(endpoint: endpoint)
            let device = try await client.finishEnrollment(enrollmentID: enrollmentID, challenge: challenge)
            deviceID = device.id
            status = "Paired with hardware-bound \(device.signatureAlgorithm) identity"
        } catch {
            status = "Pairing failed. Verify the endpoint and create a new challenge."
        }
    }
}
