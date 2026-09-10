package com.secretbroker.mobile.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyFactory
import java.security.KeyStore
import java.security.Signature
import android.security.keystore.KeyInfo
import java.util.Base64
import java.security.spec.ECGenParameterSpec

class DeviceSigner(private val alias: String = "broker-device-p256-v1") {
    fun isHardwareSigningAvailable(): Boolean {
        return runCatching {
            ensureKey()
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val privateKey = store.getKey(alias, null) as java.security.PrivateKey
            val info = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
                .getKeySpec(privateKey, KeyInfo::class.java)
            @Suppress("DEPRECATION")
            info.isInsideSecureHardware
        }.getOrDefault(false)
    }

    fun ensureKey(): ByteArray {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (!store.containsAlias(alias)) {
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false)
                .build()
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
                initialize(spec)
                generateKeyPair()
            }
        }
        return store.getCertificate(alias).publicKey.encoded
    }

    fun publicKeyPem(): String {
        val encoded = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(ensureKey())
        return "-----BEGIN PUBLIC KEY-----\n$encoded\n-----END PUBLIC KEY-----\n"
    }

    fun signEnrollment(enrollmentId: String, challenge: String): String = sign(
        "secret-broker-device-enrollment-v1\n$enrollmentId\n$challenge".toByteArray(),
    )

    fun sign(message: ByteArray): String {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = store.getKey(alias, null) ?: error("Device key is not enrolled")
        val signature = Signature.getInstance("SHA256withECDSA").apply {
            initSign(key as java.security.PrivateKey)
            update(message)
        }.sign()
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signature)
    }
}
