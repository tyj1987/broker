package com.secretbroker.mobile.otp

import java.util.concurrent.atomic.AtomicReference

object PendingTaskRegistry {
    private val tasks = AtomicReference<List<PendingOtpTask>>(emptyList())
    @Volatile private var submitter: ((OtpMatch) -> Unit)? = null

    fun replace(value: List<PendingOtpTask>, onMatch: (OtpMatch) -> Unit) {
        tasks.set(value.toList())
        submitter = onMatch
    }

    fun accept(sender: String, body: String, simBinding: String, nowMs: Long): Boolean {
        val match = OtpMatcher.match(sender, body, simBinding, tasks.get(), nowMs) ?: return false
        val currentSubmitter = submitter ?: return false
        tasks.updateAndGet { current -> current.filterNot { it.id == match.task.id } }
        currentSubmitter.invoke(match)
        return true
    }

    fun singleConsentCandidate(sender: String, nowMs: Long): PendingOtpTask? {
        val candidates = tasks.get().filter {
            it.expiresAtMs > nowMs && sender in it.senderAllowlist
        }
        return candidates.singleOrNull()
    }

    fun acceptConsent(taskId: String, sender: String, body: String, nowMs: Long): Boolean {
        val task = tasks.get().singleOrNull {
            it.id == taskId && it.expiresAtMs > nowMs && sender in it.senderAllowlist
        } ?: return false
        val match = OtpMatcher.match(sender, body, task.simBinding, listOf(task), nowMs) ?: return false
        var removed = false
        tasks.updateAndGet { current ->
            if (current.any { it.id == task.id }) {
                removed = true
                current.filterNot { it.id == task.id }
            } else current
        }
        if (!removed) return false
        submitter?.invoke(match)
        return true
    }

    fun clear() {
        tasks.set(emptyList())
        submitter = null
    }
}
