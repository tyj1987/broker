package com.secretbroker.mobile.otp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class IncomingSimResolverTest {
    @Test fun acceptsLongAndIntegerSubscriptionExtras() {
        assertEquals(IncomingSim(7, 1), IncomingSimResolver.fromValues(mapOf("subscription" to 7L, "slot" to 1)))
        assertEquals(
            IncomingSim(8, 0),
            IncomingSimResolver.fromValues(
                mapOf("android.telephony.extra.SUBSCRIPTION_INDEX" to 8, "android.telephony.extra.SLOT_INDEX" to 0L),
            ),
        )
    }

    @Test fun failsClosedForMissingInvalidOrOverflowingSubscription() {
        assertNull(IncomingSimResolver.fromValues(emptyMap()))
        assertNull(IncomingSimResolver.fromValues(mapOf("subscription" to -1)))
        assertNull(IncomingSimResolver.fromValues(mapOf("subscription" to Long.MAX_VALUE)))
        assertNull(IncomingSimResolver.fromValues(mapOf("subscription" to "7")))
    }
}
