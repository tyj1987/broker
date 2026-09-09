package com.secretbroker.mobile.otp

import android.content.Intent

data class IncomingSim(val subscriptionId: Int, val slotIndex: Int?)

object IncomingSimResolver {
    // SMS_RECEIVED commonly carries the subscription as a Long under
    // "subscription". Some Android/OEM builds use the public telephony keys.
    // If none is present we fail closed instead of guessing the default SIM.
    private val subscriptionKeys = listOf("subscription", "android.telephony.extra.SUBSCRIPTION_INDEX")
    private val slotKeys = listOf("slot", "android.telephony.extra.SLOT_INDEX")

    fun fromIntent(intent: Intent): IncomingSim? {
        val extras = intent.extras ?: return null
        val values = extras.keySet().associateWith(extras::get)
        return fromValues(values)
    }

    internal fun fromValues(values: Map<String, Any?>): IncomingSim? {
        val subscriptionId = subscriptionKeys.firstNotNullOfOrNull { key -> values[key].asNonNegativeInt() }
            ?: return null
        val slotIndex = slotKeys.firstNotNullOfOrNull { key -> values[key].asNonNegativeInt() }
        return IncomingSim(subscriptionId, slotIndex)
    }

    private fun Any?.asNonNegativeInt(): Int? {
        val number = this as? Number ?: return null
        val value = number.toLong()
        return value.takeIf { it in 0..Int.MAX_VALUE }?.toInt()
    }
}
