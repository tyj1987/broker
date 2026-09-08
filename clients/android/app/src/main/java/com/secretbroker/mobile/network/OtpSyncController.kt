package com.secretbroker.mobile.network

import com.secretbroker.mobile.otp.PendingOtpTask
import com.secretbroker.mobile.otp.PendingTaskRegistry
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Foreground-only task synchronization. Codes are submitted immediately and never persisted. */
class OtpSyncController(
    private val scope: CoroutineScope,
    private val api: BrokerDeviceApi,
    private val onTasks: (List<PendingOtpTask>) -> Unit,
    private val onState: (String) -> Unit,
) {
    private var job: Job? = null

    fun start() {
        if (job?.isActive == true) return
        job = scope.launch {
            while (isActive) {
                try {
                    val tasks = withContext(Dispatchers.IO) { api.pendingTasks() }
                    PendingTaskRegistry.replace(tasks) { match ->
                        launch(Dispatchers.IO) {
                            runCatching { api.submit(match) }
                                .onSuccess { onState("otp_submitted") }
                                .onFailure { onState("otp_submit_failed") }
                        }
                    }
                    onTasks(tasks)
                    onState("device_online")
                } catch (_: Exception) {
                    PendingTaskRegistry.clear()
                    onTasks(emptyList())
                    onState("device_offline")
                }
                delay(15_000)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
        PendingTaskRegistry.clear()
        onTasks(emptyList())
    }
}
