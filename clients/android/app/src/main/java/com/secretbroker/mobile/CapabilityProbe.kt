package com.secretbroker.mobile

import android.Manifest
import android.app.ActivityManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.PowerManager
import com.google.android.gms.common.GoogleApiAvailability
import com.secretbroker.mobile.security.DeviceSigner

data class DeviceCapabilities(
    val apiLevel: Int,
    val androidRelease: String,
    val buildDisplay: String,
    val buildIncremental: String,
    val manufacturer: String,
    val model: String,
    val receiveSmsDeclared: Boolean,
    val receiveSmsGranted: Boolean,
    val hardwareSigning: Boolean,
    val googleServicesAvailable: Boolean,
    val backgroundRestricted: Boolean,
    val batteryOptimizationExempt: Boolean,
) {
    val unattendedOtpPossible: Boolean
        get() = automaticOtpAvailable(receiveSmsGranted, hardwareSigning, backgroundRestricted)
}

internal fun automaticOtpAvailable(
    receiveSmsGranted: Boolean,
    hardwareSigning: Boolean,
    backgroundRestricted: Boolean,
): Boolean = receiveSmsGranted && hardwareSigning && !backgroundRestricted

object CapabilityProbe {
    fun inspect(context: Context): DeviceCapabilities {
        val declared = context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.GET_PERMISSIONS,
        ).requestedPermissions?.contains(Manifest.permission.RECEIVE_SMS) == true
        val granted = context.checkSelfPermission(Manifest.permission.RECEIVE_SMS) == PackageManager.PERMISSION_GRANTED
        val activityManager = context.getSystemService(ActivityManager::class.java)
        val powerManager = context.getSystemService(PowerManager::class.java)
        return DeviceCapabilities(
            apiLevel = Build.VERSION.SDK_INT,
            androidRelease = Build.VERSION.RELEASE.orEmpty().take(64),
            buildDisplay = Build.DISPLAY.orEmpty().take(128),
            buildIncremental = Build.VERSION.INCREMENTAL.orEmpty().take(128),
            manufacturer = Build.MANUFACTURER,
            model = Build.MODEL,
            receiveSmsDeclared = declared,
            receiveSmsGranted = granted,
            hardwareSigning = DeviceSigner().isHardwareSigningAvailable(),
            googleServicesAvailable = GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(context) == 0,
            backgroundRestricted = activityManager?.isBackgroundRestricted ?: true,
            batteryOptimizationExempt = powerManager?.isIgnoringBatteryOptimizations(context.packageName) ?: false,
        )
    }
}
