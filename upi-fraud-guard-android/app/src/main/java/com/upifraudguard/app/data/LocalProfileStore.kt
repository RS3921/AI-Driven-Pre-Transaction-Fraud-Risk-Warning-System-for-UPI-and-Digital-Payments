package com.upifraudguard.app.data

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/** Local demo profile gate. It is not a shared, server-authenticated user account. */
object LocalProfileStore {
    private const val PREFS = "upi_fraud_guard_profile"
    private const val NAME = "display_name"
    private const val EMAIL = "email"
    private const val VERIFIED = "authenticator_verified"
    private const val TOTP_SECRET = "totp_secret_encrypted"

    private const val ONBOARDING_COMPLETED = "onboarding_completed"

    fun hasProfile(context: Context): Boolean {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return prefs.getBoolean(VERIFIED, false) && !prefs.getString(EMAIL, null).isNullOrBlank()
    }

    fun hasCompletedOnboarding(context: Context): Boolean {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(ONBOARDING_COMPLETED, false)
    }

    fun setOnboardingCompleted(context: Context, completed: Boolean = true) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean(ONBOARDING_COMPLETED, completed).apply()
    }

    fun getName(context: Context): String {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(NAME, "") ?: ""
    }

    fun getEmail(context: Context): String {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(EMAIL, "") ?: ""
    }

    fun save(context: Context, name: String, email: String, secret: String) {
        val encryptedSecret = encrypt(secret)
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(NAME, name.trim())
            .putString(EMAIL, email.trim())
            .putString(TOTP_SECRET, encryptedSecret)
            .putBoolean(VERIFIED, true)
            .apply()
    }

    fun clear(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().apply()
    }

    private fun encrypt(value: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val encrypted = cipher.doFinal(value.toByteArray(Charsets.UTF_8))
        val payload = cipher.iv + encrypted
        return Base64.encodeToString(payload, Base64.NO_WRAP)
    }

    private fun getOrCreateKey(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return generator.generateKey()
    }

    private const val KEY_ALIAS = "upi_fraud_guard_totp_secret_v1"
}
