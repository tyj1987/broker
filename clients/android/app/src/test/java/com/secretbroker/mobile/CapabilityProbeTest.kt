package com.secretbroker.mobile

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CapabilityProbeTest {
    @Test
    fun `automatic OTP requires permission hardware and unrestricted background`() {
        assertTrue(automaticOtpAvailable(true, true, false))
        assertFalse(automaticOtpAvailable(false, true, false))
        assertFalse(automaticOtpAvailable(true, false, false))
        assertFalse(automaticOtpAvailable(true, true, true))
    }
}
