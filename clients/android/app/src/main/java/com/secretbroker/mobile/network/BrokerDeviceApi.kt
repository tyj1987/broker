package com.secretbroker.mobile.network

import com.secretbroker.mobile.otp.OtpMatch
import com.secretbroker.mobile.otp.PendingOtpTask
import com.secretbroker.mobile.security.DeviceSigner
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.URI
import java.net.URL
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID
import javax.net.ssl.HttpsURLConnection

data class DeviceRegistration(val id: String, val label: String, val state: String)

class BrokerDeviceApi(
    endpoint: String,
    private val deviceId: String,
    private val signer: DeviceSigner,
    private val connectTimeoutMs: Int = 10_000,
    private val readTimeoutMs: Int = 15_000,
) {
    private val origin: URI = validateOrigin(endpoint)

    companion object {
        private const val MAX_RESPONSE_BYTES = 256 * 1024

        internal fun validateOrigin(endpoint: String): URI = URI(endpoint).normalize().also {
        require(it.scheme == "https" && it.userInfo == null && it.host != null)
        require(it.port == -1 || it.port == 443)
        val host = it.host.lowercase()
        require(!host.matches(Regex("[0-9.]+")))
        require(':' !in host)
        require(host != "localhost" && !host.endsWith(".localhost"))
        require(!host.endsWith(".local") && !host.endsWith(".internal"))
        require(it.path.isNullOrEmpty() || it.path == "/")
        require(it.query == null && it.fragment == null)
        }

        fun approvalUrl(endpoint: String): String = validateOrigin(endpoint).resolve("/approvals").toString()

        fun finishEnrollment(
            endpoint: String,
            enrollmentId: String,
            challenge: String,
            signer: DeviceSigner,
        ): DeviceRegistration {
            require(enrollmentId.matches(Regex("[a-f0-9-]{36}"))) { "Invalid enrollment ID" }
            require(challenge.matches(Regex("[A-Za-z0-9_-]{32,128}"))) { "Invalid enrollment challenge" }
            val body = JSONObject().apply {
                put("enrollment_id", enrollmentId)
                put("public_key_pem", signer.publicKeyPem())
                put("signature_algorithm", "p256-sha256")
                put("signature", signer.signEnrollment(enrollmentId, challenge))
            }.toString()
            val origin = validateOrigin(endpoint)
            val response = request(origin, "POST", "/api/v2/devices/enroll/finish", body, emptyMap(), 10_000, 15_000)
            val value = JSONObject(response)
            return DeviceRegistration(value.getString("id"), value.getString("label"), value.getString("state"))
        }

        private fun request(
            origin: URI,
            method: String,
            path: String,
            body: String,
            headers: Map<String, String>,
            connectTimeoutMs: Int,
            readTimeoutMs: Int,
        ): String {
            val connection = URL(origin.resolve(path).toString()).openConnection() as HttpsURLConnection
            connection.requestMethod = method
            connection.connectTimeout = connectTimeoutMs
            connection.readTimeout = readTimeoutMs
            connection.instanceFollowRedirects = false
            connection.setRequestProperty("Accept", "application/json")
            headers.forEach(connection::setRequestProperty)
            if (body.isNotEmpty()) {
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json")
                connection.outputStream.use { it.write(body.toByteArray()) }
            }
            try {
                if (connection.responseCode !in 200..299) {
                    connection.errorStream?.close()
                    throw BrokerException("Broker rejected the request", connection.responseCode)
                }
                return connection.inputStream.use { input ->
                    val output = ByteArrayOutputStream()
                    val buffer = ByteArray(8192)
                    while (output.size() <= MAX_RESPONSE_BYTES) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        output.write(buffer, 0, count)
                    }
                    val limited = output.toByteArray()
                    require(limited.size <= MAX_RESPONSE_BYTES) { "Broker response is too large" }
                    limited.toString(Charsets.UTF_8)
                }
            } finally {
                connection.disconnect()
            }
        }
    }

    fun pendingTasks(): List<PendingOtpTask> {
        val path = "/api/v2/devices/$deviceId/otp-tasks"
        val response = signedRequest("GET", path, "")
        val tasks = JSONObject(response).getJSONArray("tasks")
        return (0 until tasks.length()).map { index ->
            val item = tasks.getJSONObject(index)
            PendingOtpTask(
                id = item.getString("id"),
                provider = item.getString("provider"),
                simBinding = item.getString("sim_binding"),
                templateGroup = item.getString("template_group"),
                challenge = item.getString("challenge"),
                senderAllowlist = item.getJSONArray("sender_allowlist").let { senders ->
                    (0 until senders.length()).map(senders::getString).toSet()
                },
                expiresAtMs = java.time.Instant.parse(item.getString("expires_at")).toEpochMilli(),
            )
        }
    }

    fun submit(match: OtpMatch) {
        val path = "/api/v2/devices/$deviceId/otp-tasks/${match.task.id}/submit"
        val body = canonicalObject(
            mapOf("challenge" to match.task.challenge, "code" to match.code, "sim_binding" to match.task.simBinding),
        )
        signedRequest("POST", path, body)
    }

    fun suspendDevice() {
        signedRequest("POST", "/api/v2/devices/$deviceId/suspend", "{}")
    }

    private fun signedRequest(method: String, path: String, body: String): String {
        val timestamp = System.currentTimeMillis()
        val nonce = UUID.randomUUID().toString()
        val message = listOf(
            "secret-broker-device-request-v1",
            deviceId,
            timestamp.toString(),
            nonce,
            method,
            path,
            sha256Base64Url(body.toByteArray()),
        ).joinToString("\n")
        return request(
            origin, method, path, body,
            mapOf(
                "X-Broker-Device-Timestamp" to timestamp.toString(),
                "X-Broker-Device-Nonce" to nonce,
                "X-Broker-Device-Signature" to signer.sign(message.toByteArray()),
            ),
            connectTimeoutMs,
            readTimeoutMs,
        )
    }

    private fun canonicalObject(values: Map<String, String>): String = values.toSortedMap().entries.joinToString(
        prefix = "{", postfix = "}", separator = ",",
    ) { (key, value) -> "${JSONObject.quote(key)}:${JSONObject.quote(value)}" }

    private fun sha256Base64Url(value: ByteArray): String = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(MessageDigest.getInstance("SHA-256").digest(value))
}

class BrokerException(message: String, val status: Int) : Exception(message)
