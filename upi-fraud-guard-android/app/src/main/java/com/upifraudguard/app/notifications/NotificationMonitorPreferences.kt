package com.upifraudguard.app.notifications

import android.content.Context
import java.text.DateFormat
import java.util.Date

/** User controls for which notification sources may be sent for a check. */
object NotificationMonitorPreferences {
    private const val PREFS = "upi_fraud_guard_notification_monitor"
    private const val ENABLED = "enabled"
    private const val TELEGRAM = "telegram"
    private const val WHATSAPP = "whatsapp"
    private const val MESSAGES = "messages"
    private const val OTHER_APPS = "other_apps"
    private const val LAST_BACKEND_OK = "last_backend_ok"
    private const val LAST_CHECK_AT = "last_check_at"

    data class Settings(
        val enabled: Boolean,
        val telegram: Boolean,
        val whatsapp: Boolean,
        val messages: Boolean,
        val otherApps: Boolean,
    )

    fun read(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).let { prefs ->
        Settings(
            enabled = prefs.getBoolean(ENABLED, true),
            telegram = prefs.getBoolean(TELEGRAM, true),
            whatsapp = prefs.getBoolean(WHATSAPP, false),
            messages = prefs.getBoolean(MESSAGES, true),
            otherApps = prefs.getBoolean(OTHER_APPS, false),
        )
    }

    fun update(context: Context, transform: (Settings) -> Settings) {
        val updated = transform(read(context))
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putBoolean(ENABLED, updated.enabled)
            .putBoolean(TELEGRAM, updated.telegram)
            .putBoolean(WHATSAPP, updated.whatsapp)
            .putBoolean(MESSAGES, updated.messages)
            .putBoolean(OTHER_APPS, updated.otherApps)
            .apply()
    }

    fun recordBackendState(context: Context, reachable: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putBoolean(LAST_BACKEND_OK, reachable)
            .putLong(LAST_CHECK_AT, System.currentTimeMillis())
            .apply()
    }

    fun backendStateLabel(context: Context): String {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (!prefs.contains(LAST_BACKEND_OK)) return "No background check result yet"
        val state = if (prefs.getBoolean(LAST_BACKEND_OK, false)) {
            "Last notification check reached the backend"
        } else {
            "Backend unreachable — notification was not analyzed"
        }
        val timestamp = prefs.getLong(LAST_CHECK_AT, 0L)
        val whenChecked = if (timestamp > 0L) DateFormat.getDateTimeInstance().format(Date(timestamp)) else "unknown time"
        return "$state ($whenChecked)"
    }

    const val TELEGRAM_PACKAGE = "org.telegram.messenger"
    const val WHATSAPP_PACKAGE = "com.whatsapp"
    private val MESSAGES_PACKAGES = setOf(
        "com.google.android.apps.messaging",
        "com.android.mms",
        "com.samsung.android.messaging",
    )

    fun sourceEnabled(packageName: String, settings: Settings): Boolean = when (packageName) {
        TELEGRAM_PACKAGE -> settings.telegram
        WHATSAPP_PACKAGE -> settings.whatsapp
        in MESSAGES_PACKAGES -> settings.messages
        else -> settings.otherApps
    }
}
