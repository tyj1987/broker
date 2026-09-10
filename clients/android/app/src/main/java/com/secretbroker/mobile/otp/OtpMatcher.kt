package com.secretbroker.mobile.otp

data class PendingOtpTask(
    val id: String,
    val provider: String,
    val simBinding: String,
    val templateGroup: String,
    val challenge: String,
    val senderAllowlist: Set<String>,
    val expiresAtMs: Long,
)

data class OtpMatch(val task: PendingOtpTask, val code: String)

object OtpMatcher {
    private val code = Regex("(?<![A-Za-z0-9])[0-9]{4,10}(?![A-Za-z0-9])")

    fun match(sender: String, body: String, simBinding: String, tasks: List<PendingOtpTask>, nowMs: Long): OtpMatch? {
        val candidates = tasks.filter {
            it.expiresAtMs > nowMs && it.simBinding == simBinding && sender in it.senderAllowlist
        }
        if (candidates.size != 1) return null
        val codes = code.findAll(body).map { it.value }.distinct().toList()
        if (codes.size != 1) return null
        return OtpMatch(candidates.single(), codes.single())
    }
}
