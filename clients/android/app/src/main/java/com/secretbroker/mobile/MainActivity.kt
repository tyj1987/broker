package com.secretbroker.mobile

import android.Manifest
import android.content.Context
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import com.secretbroker.mobile.network.BrokerDeviceApi
import com.secretbroker.mobile.network.OtpSyncController
import com.secretbroker.mobile.otp.PendingOtpTask
import com.secretbroker.mobile.otp.ObservedSim
import com.secretbroker.mobile.otp.SimBindings
import com.secretbroker.mobile.otp.SmsConsentCoordinator
import com.secretbroker.mobile.security.DeviceSigner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    private val signer = DeviceSigner()
    private var capabilities by mutableStateOf<DeviceCapabilities?>(null)
    private var endpoint by mutableStateOf("https://broker.52trz.com")
    private var enrollmentId by mutableStateOf("")
    private var enrollmentChallenge by mutableStateOf("")
    private var deviceId by mutableStateOf<String?>(null)
    private var locallySuspended by mutableStateOf(false)
    private var state by mutableStateOf("not_paired")
    private var pendingTasks by mutableStateOf<List<PendingOtpTask>>(emptyList())
    private var observedSims by mutableStateOf<List<ObservedSim>>(emptyList())
    private var simBindingDrafts by mutableStateOf<Map<Int, String>>(emptyMap())
    private var sync: OtpSyncController? = null
    private lateinit var consent: SmsConsentCoordinator

    private val requestSms = registerForActivityResult(ActivityResultContracts.RequestPermission()) {
        capabilities = CapabilityProbe.inspect(this)
    }
    private val requestConsent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        consent.handleResult(it.resultCode, it.data)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        val preferences = getSharedPreferences("device-registration", Context.MODE_PRIVATE)
        endpoint = preferences.getString("endpoint", endpoint) ?: endpoint
        deviceId = preferences.getString("device_id", null)
        locallySuspended = preferences.getBoolean("device_suspended", false)
        observedSims = SimBindings.observed(this)
        consent = SmsConsentCoordinator(this, requestConsent::launch) { state = it }
        capabilities = CapabilityProbe.inspect(this)
        setContent {
            MaterialTheme {
                Column(
                    modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text("Secret Broker device", style = MaterialTheme.typography.headlineSmall)
                    val value = capabilities
                    Text("${value?.manufacturer ?: ""} ${value?.model ?: ""} · API ${value?.apiLevel ?: "-"}")
                    Text(if (value?.hardwareSigning == true) "P-256 signing key is hardware-backed" else "Hardware-backed signing is unavailable")
                    Text(if (value?.unattendedOtpPossible == true) "Automatic OTP capability available" else "Automatic OTP unavailable; confirmation or manual input is required")
                    Text(if (value?.googleServicesAvailable == true) "SMS User Consent fallback available (confirmation required)" else "Google SMS consent fallback unavailable")
                    Text("State: $state")

                    if (value?.receiveSmsGranted != true) {
                        Button(onClick = { requestSms.launch(Manifest.permission.RECEIVE_SMS) }) {
                            Text("Check SMS permission")
                        }
                    }

                    if (deviceId == null) {
                        OutlinedTextField(endpoint, { endpoint = it.trim() }, label = { Text("Broker HTTPS origin") })
                        OutlinedTextField(enrollmentId, { enrollmentId = it.trim() }, label = { Text("Enrollment ID") })
                        OutlinedTextField(
                            enrollmentChallenge,
                            { enrollmentChallenge = it.trim() },
                            label = { Text("Short-lived challenge") },
                            visualTransformation = PasswordVisualTransformation(),
                        )
                        Button(
                            onClick = { pair(preferences) },
                            enabled = value?.hardwareSigning == true && enrollmentId.isNotBlank() && enrollmentChallenge.isNotBlank(),
                        ) {
                            Text("Pair this device")
                        }
                    } else {
                        Text("Paired device: ${deviceId!!.take(8)}…")
                        if (locallySuspended) {
                            Text("Automation is suspended at the Broker. An administrator must reactivate this device before it can reconnect.")
                            Button(onClick = { retryAfterAdminReactivation(preferences) }) {
                                Text("Check after administrator reactivation")
                            }
                        } else {
                            Text("Pending OTP tasks: ${pendingTasks.size}")
                            val expectedBindings = pendingTasks.map { it.simBinding }.distinct()
                            if (expectedBindings.isNotEmpty()) Text("Expected SIM bindings: ${expectedBindings.joinToString()}")
                            Button(onClick = { refreshObservedSims() }) { Text("Refresh observed SIMs") }
                            if (observedSims.isEmpty()) {
                                Text("No receiving SIM has been observed. Receive one test message, then refresh.")
                            }
                            observedSims.forEach { sim ->
                                val slot = sim.slotIndex?.plus(1)?.toString() ?: "unknown"
                                Text("SIM slot $slot · subscription ${sim.subscriptionId} · ${sim.binding ?: "not bound"}")
                                OutlinedTextField(
                                    value = simBindingDrafts[sim.subscriptionId] ?: sim.binding.orEmpty(),
                                    onValueChange = { value ->
                                        simBindingDrafts = simBindingDrafts + (sim.subscriptionId to value.trim())
                                    },
                                    label = { Text("Binding for SIM slot $slot") },
                                )
                                val draft = simBindingDrafts[sim.subscriptionId] ?: sim.binding.orEmpty()
                                Button(
                                    onClick = { bindSim(sim.subscriptionId) },
                                    enabled = draft in expectedBindings,
                                ) { Text("Bind this SIM") }
                            }
                            val consentSenders = pendingTasks.flatMap { it.senderAllowlist }.distinct()
                            if (value?.googleServicesAvailable == true && consentSenders.size == 1) {
                                Button(onClick = { consent.start(consentSenders.single()) }) {
                                    Text("Wait for one SMS with confirmation")
                                }
                            }
                            Button(onClick = { suspendAutomation(preferences) }) { Text("Pause automation") }
                        }
                        Button(onClick = { unpair(preferences) }) { Text("Remove local pairing") }
                    }
                }
            }
        }
    }

    override fun onStart() {
        super.onStart()
        refreshObservedSims()
        startSync()
    }

    override fun onStop() {
        sync?.stop()
        sync = null
        consent.close()
        super.onStop()
    }

    private fun pair(preferences: android.content.SharedPreferences) {
        if (!signer.isHardwareSigningAvailable()) {
            enrollmentChallenge = ""
            state = "hardware_signing_required"
            return
        }
        state = "pairing"
        lifecycleScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    BrokerDeviceApi.finishEnrollment(endpoint, enrollmentId, enrollmentChallenge, signer)
                }
            }.onSuccess { registration ->
                deviceId = registration.id
                enrollmentId = ""
                enrollmentChallenge = ""
                preferences.edit().putString("endpoint", endpoint).putString("device_id", registration.id).apply()
                state = "paired"
                startSync()
            }.onFailure {
                enrollmentChallenge = ""
                state = "pairing_failed"
            }
        }
    }

    private fun startSync() {
        val id = deviceId ?: return
        if (locallySuspended) return
        if (sync != null) return
        sync = OtpSyncController(
            lifecycleScope,
            BrokerDeviceApi(endpoint, id, signer),
            { pendingTasks = it },
            { state = it },
        ).also { it.start() }
    }

    private fun unpair(preferences: android.content.SharedPreferences) {
        sync?.stop()
        sync = null
        preferences.edit().remove("device_id").remove("endpoint").remove("device_suspended").remove("last_cold_receive_ms").apply()
        SimBindings.clear(this)
        deviceId = null
        locallySuspended = false
        pendingTasks = emptyList()
        state = "not_paired"
    }

    private fun refreshObservedSims() {
        observedSims = SimBindings.observed(this)
    }

    private fun bindSim(subscriptionId: Int) {
        val binding = simBindingDrafts[subscriptionId].orEmpty()
        runCatching {
            require(pendingTasks.any { it.simBinding == binding }) { "Binding is not present in an active task" }
            SimBindings.bind(this, subscriptionId, binding)
        }
            .onSuccess {
                state = "sim_bound"
                refreshObservedSims()
            }
            .onFailure { state = "sim_binding_failed" }
    }

    private fun suspendAutomation(preferences: android.content.SharedPreferences) {
        val id = deviceId ?: return
        state = "suspending"
        lifecycleScope.launch {
            runCatching {
                withContext(Dispatchers.IO) { BrokerDeviceApi(endpoint, id, signer).suspendDevice() }
            }.onSuccess {
                sync?.stop()
                sync = null
                pendingTasks = emptyList()
                locallySuspended = true
                preferences.edit().putBoolean("device_suspended", true).apply()
                state = "suspended"
            }.onFailure { state = "suspension_failed" }
        }
    }

    private fun retryAfterAdminReactivation(preferences: android.content.SharedPreferences) {
        val id = deviceId ?: return
        state = "checking_reactivation"
        lifecycleScope.launch {
            runCatching {
                withContext(Dispatchers.IO) { BrokerDeviceApi(endpoint, id, signer).pendingTasks() }
            }.onSuccess { tasks ->
                pendingTasks = tasks
                locallySuspended = false
                preferences.edit().putBoolean("device_suspended", false).apply()
                state = "reactivated"
                startSync()
            }.onFailure { state = "still_suspended_or_offline" }
        }
    }
}
