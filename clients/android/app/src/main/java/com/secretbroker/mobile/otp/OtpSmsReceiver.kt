package com.secretbroker.mobile.otp

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import com.secretbroker.mobile.network.BrokerDeviceApi
import com.secretbroker.mobile.security.DeviceSigner
import kotlin.concurrent.thread

class OtpSmsReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return
        val preferences = context.getSharedPreferences("device-registration", Context.MODE_PRIVATE)
        val endpoint = preferences.getString("endpoint", null) ?: return
        val deviceId = preferences.getString("device_id", null) ?: return
        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        val sender = messages.firstOrNull()?.originatingAddress ?: return
        val body = messages.joinToString(separator = "") { it.messageBody ?: "" }
        val incomingSim = IncomingSimResolver.fromIntent(intent) ?: return
        val observed = SimBindings.observe(context, incomingSim, System.currentTimeMillis())
        val binding = observed.binding ?: return
        if (PendingTaskRegistry.accept(sender, body, binding, System.currentTimeMillis())) return

        // A process killed by the OS has no in-memory task registry. Fetch the
        // already-authorized tasks during this system broadcast, match locally,
        // and submit only one unambiguous result. No SMS or OTP is persisted.
        val now = System.currentTimeMillis()
        synchronized(OtpSmsReceiver::class.java) {
            if (now - preferences.getLong("last_cold_receive_ms", 0) < 15_000) return
            preferences.edit().putLong("last_cold_receive_ms", now).apply()
        }
        val pendingResult = goAsync()
        thread(name = "broker-otp-cold-receive", isDaemon = true) {
            try {
                val api = BrokerDeviceApi(endpoint, deviceId, DeviceSigner(), 3_000, 3_000)
                val match = OtpMatcher.match(sender, body, binding, api.pendingTasks(), System.currentTimeMillis())
                if (match != null) api.submit(match)
            } catch (_: Exception) {
                // Fail closed. The user can retry through the foreground or consent flow.
            } finally {
                pendingResult.finish()
            }
        }
    }
}
