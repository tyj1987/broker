package com.secretbroker.mobile.otp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class OtpMatcherTest {
    private val task = PendingOtpTask("t1", "aliyun", "sim-a", "login", "challenge", setOf("95500"), 2_000)

    @Test fun acceptsOneBoundTaskAndOneCode() {
        assertEquals("482913", OtpMatcher.match("95500", "code 482913", "sim-a", listOf(task), 1_000)?.code)
    }

    @Test fun rejectsUnknownSenderSimExpiredAmbiguousAndMultipleCodes() {
        assertNull(OtpMatcher.match("other", "482913", "sim-a", listOf(task), 1_000))
        assertNull(OtpMatcher.match("95500", "482913", "sim-b", listOf(task), 1_000))
        assertNull(OtpMatcher.match("95500", "482913", "sim-a", listOf(task), 2_001))
        assertNull(OtpMatcher.match("95500", "482913", "sim-a", listOf(task, task.copy(id = "t2")), 1_000))
        assertNull(OtpMatcher.match("95500", "482913 or 123456", "sim-a", listOf(task), 1_000))
    }
}
