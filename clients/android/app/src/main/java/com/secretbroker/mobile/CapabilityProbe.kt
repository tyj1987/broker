package com.secretbroker.mobile

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.google.android.gms.common.GoogleApiAvailability
import com.secretbroker.mobile.security.DeviceSigner

data class DeviceCapabilities(
    val apiLevel: Int,
    val manufacturer: String,
    val model: String,
    val receiveSmsDeclared: Boolean,
    val receiveSmsGranted: Boolean,
    val hardwareSigning: Boolean,
    val googleServicesAvailable: Boolean,
) {
    val unattendedOtpPossible: Boolean get() = receiveSmsGranted && hardwareSigning
}

object CapabilityProbe {
    fun inspect(context: Context): DeviceCapabilities {
        val declared = context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.GET_PERMISSIONS,
        ).requestedPermissions?.contains(Manifest.permission.RECEIVE_SMS) == true
        val granted = context.checkSelfPermission(Manifest.permission.RECEIVE_SMS) == PackageManager.PERMISSION_GRANTED
        return DeviceCapabilities(
            apiLevel = Build.VERSION.SDK_INT,
            manufacturer = Build.MANUFACTURER,
            model = Build.MODEL,
            receiveSmsDeclared = declared,
            receiveSmsGranted = granted,
            hardwareSigning = DeviceSigner().isHardwareSigningAvailable(),
            googleServicesAvailable = GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(context) == 0,
        )
    }
}
