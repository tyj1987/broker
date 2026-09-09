package com.secretbroker.mobile.network

import com.secretbroker.mobile.security.DeviceSigner
import org.junit.Assert.assertThrows
import org.junit.Assert.assertEquals
import org.junit.Test

class EndpointPolicyTest {
    @Test fun approvalUrlIsPinnedToTheValidatedBrokerOrigin() {
        assertEquals("https://broker.example/approvals", BrokerDeviceApi.approvalUrl("https://broker.example"))
        assertThrows(IllegalArgumentException::class.java) {
            BrokerDeviceApi.approvalUrl("https://broker.example/redirect?to=https://evil.invalid")
        }
    }

    @Test fun rejectsNonHttpsUserInfoIpLiteralAndCustomPort() {
        val signer = DeviceSigner("test-only")
        assertThrows(IllegalArgumentException::class.java) { BrokerDeviceApi("http://broker.example", "d", signer) }
        assertThrows(IllegalArgumentException::class.java) { BrokerDeviceApi("https://user@broker.example", "d", signer) }
        assertThrows(IllegalArgumentException::class.java) { BrokerDeviceApi("https://127.0.0.1", "d", signer) }
        assertThrows(IllegalArgumentException::class.java) { BrokerDeviceApi("https://broker.example:8443", "d", signer) }
    }

    @Test fun rejectsIpv6LocalNamesPathsQueriesAndFragments() {
        val signer = DeviceSigner("test-only")
        listOf(
            "https://[::1]",
            "https://localhost",
            "https://broker.local",
            "https://broker.internal",
            "https://broker.example/path",
            "https://broker.example?next=https://evil.invalid",
            "https://broker.example/#fragment",
        ).forEach { endpoint ->
            assertThrows(IllegalArgumentException::class.java) { BrokerDeviceApi(endpoint, "d", signer) }
        }
    }
}
