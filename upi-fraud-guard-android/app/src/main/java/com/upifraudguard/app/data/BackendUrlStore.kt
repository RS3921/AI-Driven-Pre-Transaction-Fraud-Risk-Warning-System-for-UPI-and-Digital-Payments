package com.upifraudguard.app.data

import android.content.Context
import android.net.Uri
import com.upifraudguard.app.BuildConfig

/** Stores the backend address on this device so emulator and phone builds can share one APK. */
object BackendUrlStore {
    private const val PREFS = "upi_fraud_guard_settings"
    private const val BASE_URL = "backend_base_url"

    fun get(context: Context): String = context
        .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        .getString(BASE_URL, null)
        ?: BuildConfig.API_BASE_URL

    fun save(context: Context, value: String): String {
        val normalized = normalize(value)
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(BASE_URL, normalized)
            .apply()
        return normalized
    }

    fun normalize(value: String): String {
        var candidate = value.trim()
        require(candidate.isNotEmpty()) { "Enter the computer's IP address or backend URL." }
        if (!candidate.contains("://")) candidate = "http://$candidate"
        if (!candidate.endsWith('/')) candidate += "/"

        val parsed = Uri.parse(candidate)
        require(parsed.scheme in listOf("http", "https") && !parsed.host.isNullOrBlank()) {
            "Use a valid address, for example https://fraud-api.example.com/"
        }
        require(parsed.query == null && parsed.fragment == null) {
            "Enter only the backend address, without a query or fragment."
        }
        return candidate
    }
}
