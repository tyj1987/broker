package com.secretbroker.mobile.otp

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import androidx.core.content.ContextCompat
import com.google.android.gms.auth.api.phone.SmsRetriever
import com.google.android.gms.common.api.CommonStatusCodes
import com.google.android.gms.common.api.Status

/** User-present fallback for a single, unambiguous pending OTP task. */
class SmsConsentCoordinator(
    private val activity: Activity,
    private val launchConsent: (Intent) -> Unit,
    private val onState: (String) -> Unit,
) {
    private var registered = false
    private var expected: Expected? = null

    private data class Expected(val taskId: String, val sender: String, val expiresAtMs: Long)

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action != SmsRetriever.SMS_RETRIEVED_ACTION) return
            val status = if (Build.VERSION.SDK_INT >= 33) {
                intent.getParcelableExtra(SmsRetriever.EXTRA_STATUS, Status::class.java)
            } else {
                @Suppress("DEPRECATION")
                intent.getParcelableExtra(SmsRetriever.EXTRA_STATUS)
            } ?: return fail("consent_status_missing")
            when (status.statusCode) {
                CommonStatusCodes.SUCCESS -> {
                    val consent = if (Build.VERSION.SDK_INT >= 33) {
                        intent.getParcelableExtra(SmsRetriever.EXTRA_CONSENT_INTENT, Intent::class.java)
                    } else {
                        @Suppress("DEPRECATION")
                        intent.getParcelableExtra(SmsRetriever.EXTRA_CONSENT_INTENT)
                    }
                    if (consent == null) fail("consent_intent_missing") else launchConsent(consent)
                }
                CommonStatusCodes.TIMEOUT -> fail("consent_timeout")
                else -> fail("consent_unavailable")
            }
        }
    }

    fun start(sender: String): Boolean {
        require(sender.isNotBlank() && sender.length <= 64)
        val task = PendingTaskRegistry.singleConsentCandidate(sender, System.currentTimeMillis())
            ?: return false.also { onState("consent_ambiguous_or_no_task") }
        expected = Expected(task.id, sender, task.expiresAtMs)
        register()
        SmsRetriever.getClient(activity).startSmsUserConsent(sender)
            .addOnSuccessListener { onState("consent_waiting") }
            .addOnFailureListener { fail("consent_start_failed") }
        return true
    }

    fun handleResult(resultCode: Int, data: Intent?) {
        val value = expected ?: return
        val now = System.currentTimeMillis()
        if (resultCode != Activity.RESULT_OK || data == null || value.expiresAtMs <= now) {
            fail("consent_denied_or_expired")
            return
        }
        val body = data.getStringExtra(SmsRetriever.EXTRA_SMS_MESSAGE)
        val accepted = body != null && PendingTaskRegistry.acceptConsent(
            value.taskId,
            value.sender,
            body,
            now,
        )
        expected = null
        onState(if (accepted) "consent_submitted" else "consent_message_mismatch")
    }

    fun close() {
        expected = null
        if (registered) {
            activity.unregisterReceiver(receiver)
            registered = false
        }
    }

    private fun register() {
        if (registered) return
        val filter = IntentFilter(SmsRetriever.SMS_RETRIEVED_ACTION)
        ContextCompat.registerReceiver(
            activity,
            receiver,
            filter,
            SmsRetriever.SEND_PERMISSION,
            null,
            ContextCompat.RECEIVER_EXPORTED,
        )
        registered = true
    }

    private fun fail(state: String) {
        expected = null
        onState(state)
    }
}
