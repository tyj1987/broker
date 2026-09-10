package com.secretbroker.mobile.otp

import android.content.Context
import androidx.core.content.edit

data class ObservedSim(
    val subscriptionId: Int,
    val slotIndex: Int?,
    val lastSeenMs: Long,
    val binding: String?,
)

object SimBindings {
    private const val PREFERENCES = "sim-bindings"
    private const val OBSERVED_IDS = "observed.ids"

    fun observe(context: Context, incoming: IncomingSim, nowMs: Long): ObservedSim {
        require(incoming.subscriptionId >= 0)
        val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
        val ids = preferences.getStringSet(OBSERVED_IDS, emptySet()).orEmpty().toMutableSet()
        val previousForSlot = incoming.slotIndex?.let { preferences.getInt("slot.$it.subscription", -1) }
            ?.takeIf { it >= 0 && it != incoming.subscriptionId }
        val previousSlot = preferences.getInt("observed.${incoming.subscriptionId}.slot", -1).takeIf { it >= 0 }
        val movedSlots = incoming.slotIndex != null && previousSlot != null && previousSlot != incoming.slotIndex
        if (previousForSlot != null) ids.remove(previousForSlot.toString())
        ids.add(incoming.subscriptionId.toString())
        preferences.edit(commit = true) {
            putStringSet(OBSERVED_IDS, ids)
            if (previousForSlot != null) {
                remove("binding.$previousForSlot")
                remove("observed.$previousForSlot.slot")
                remove("observed.$previousForSlot.last")
            }
            if (movedSlots) remove("binding.${incoming.subscriptionId}")
            putInt("observed.${incoming.subscriptionId}.slot", incoming.slotIndex ?: -1)
            putLong("observed.${incoming.subscriptionId}.last", nowMs)
            if (incoming.slotIndex != null) putInt("slot.${incoming.slotIndex}.subscription", incoming.subscriptionId)
        }
        return ObservedSim(
            incoming.subscriptionId,
            incoming.slotIndex,
            nowMs,
            preferences.getString("binding.${incoming.subscriptionId}", null),
        )
    }

    fun bind(context: Context, subscriptionId: Int, opaqueBinding: String) {
        require(subscriptionId >= 0)
        require(opaqueBinding.matches(Regex("[a-z0-9][a-z0-9._:-]{0,127}")))
        val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
        require(subscriptionId.toString() in preferences.getStringSet(OBSERVED_IDS, emptySet()).orEmpty()) {
            "SIM subscription has not been observed receiving a message"
        }
        preferences.edit(commit = true) {
            putString("binding.$subscriptionId", opaqueBinding)
        }
    }

    fun resolve(context: Context, subscriptionId: Int): String? {
        if (subscriptionId < 0) return null
        return context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .getString("binding.$subscriptionId", null)
    }

    fun observed(context: Context): List<ObservedSim> {
        val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
        return preferences.getStringSet(OBSERVED_IDS, emptySet()).orEmpty().mapNotNull { raw ->
            val id = raw.toIntOrNull()?.takeIf { it >= 0 } ?: return@mapNotNull null
            val lastSeen = preferences.getLong("observed.$id.last", -1).takeIf { it >= 0 } ?: return@mapNotNull null
            ObservedSim(
                subscriptionId = id,
                slotIndex = preferences.getInt("observed.$id.slot", -1).takeIf { it >= 0 },
                lastSeenMs = lastSeen,
                binding = preferences.getString("binding.$id", null),
            )
        }.sortedWith(compareBy<ObservedSim> { it.slotIndex ?: Int.MAX_VALUE }.thenBy { it.subscriptionId })
    }

    fun clear(context: Context) {
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE).edit(commit = true) { clear() }
    }
}
