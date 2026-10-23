package com.upifraudguard.app.notifications

import android.Manifest
import android.app.PendingIntent
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.upifraudguard.app.R
import com.upifraudguard.app.MainActivity
import com.upifraudguard.app.data.RiskCheckResponse

object RiskWarningNotifications {
    private const val CHANNEL_ID = "fraud_warnings"

    fun show(context: Context, result: RiskCheckResponse, historyMessage: String? = null) {
        if (result.verdict == "Safe") return
        if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS,
            ) != PackageManager.PERMISSION_GRANTED
        ) return

        val manager = context.getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    "UPI risk warnings",
                    NotificationManager.IMPORTANCE_HIGH,
                ),
            )
        }

        val reason = result.reasons.firstOrNull()
            ?: "Pause and verify the payment independently before proceeding."
        val openHistoryIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(MainActivity.EXTRA_OPEN_HISTORY, true)
            putExtra(MainActivity.EXTRA_HISTORY_MESSAGE, historyMessage)
        }
        val detailsPendingIntent = PendingIntent.getActivity(
            context,
            historyMessage?.hashCode() ?: (System.currentTimeMillis() % Int.MAX_VALUE).toInt(),
            openHistoryIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val score = "Risk score: ${"%.0f".format(result.riskScore * 100)}%"
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle("${result.verdict} · $score")
            .setContentText(reason)
            .setStyle(NotificationCompat.BigTextStyle().bigText("$score\n$reason\nTap to see the full history details."))
            .setContentIntent(detailsPendingIntent)
            .setAutoCancel(true)
            .build()

        runCatching {
            NotificationManagerCompat.from(context)
                .notify((System.currentTimeMillis() % Int.MAX_VALUE).toInt(), notification)
        }
    }
}
