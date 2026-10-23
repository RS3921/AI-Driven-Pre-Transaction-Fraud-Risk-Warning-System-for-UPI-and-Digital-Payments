package com.upifraudguard.app.notifications

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Base64
import com.upifraudguard.app.data.BackendUrlStore
import com.upifraudguard.app.data.ApiTokenStore
import com.upifraudguard.app.data.RiskCheckRequest
import com.upifraudguard.app.data.RiskRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.security.MessageDigest
import java.util.Locale

/**
 * Opt-in notification monitor. Candidate text is sent to the configured
 * Risk Guard API for scoring; the backend currently keeps checks in its
 * local audit database. Android grants access only after the user enables
 * this listener in system Settings.
 */
class FraudNotificationListener : NotificationListenerService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val repository by lazy {
        RiskRepository(
            { BackendUrlStore.get(this@FraudNotificationListener) },
            { ApiTokenStore.get(this@FraudNotificationListener) },
        )
    }
    // Telegram may reuse a notification ID as a conversation is updated.
    // Deduplicate by normalized message content instead, and only briefly.
    private val recentCandidates = LinkedHashMap<String, Long>()

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        if (sbn.packageName == packageName) return
        val extras = sbn.notification.extras ?: return
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString().orEmpty()
        val body = buildList {
            extras.getCharSequence(Notification.EXTRA_TEXT)?.toString()?.let(::add)
            extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()?.let(::add)
            extras.getCharSequenceArray(Notification.EXTRA_TEXT_LINES)?.forEach { add(it.toString()) }
        }.distinct().joinToString(" ")
        val text = listOf(title, body).filter(String::isNotBlank).joinToString(" — ").take(2000)
        if (text.isBlank()) return
        val monitorSettings = NotificationMonitorPreferences.read(this)
        if (!monitorSettings.enabled || !NotificationMonitorPreferences.sourceEnabled(sbn.packageName, monitorSettings)) return
        // Filter every source, including Telegram, before sending text to the
        // backend. Ordinary conversation notifications are ignored.
        if (!isPaymentRelated(text)) return

        // Avoid rescoring identical notification updates, without dropping
        // later messages that share the same Telegram notification ID.
        val normalizedText = text.lowercase(Locale.ROOT).replace(Regex("\\s+"), " ").trim()
        val textDigest = MessageDigest.getInstance("SHA-256")
            .digest(normalizedText.toByteArray(Charsets.UTF_8))
        val digestKey = Base64.encodeToString(
            textDigest,
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
        )
        val key = "${sbn.packageName}:${sbn.id}:$digestKey"
        val now = System.currentTimeMillis()
        synchronized(recentCandidates) {
            val expiredBefore = now - DEDUP_WINDOW_MS
            recentCandidates.filterValues { it < expiredBefore }.keys.toList().forEach(recentCandidates::remove)
            if (recentCandidates.containsKey(key)) return
            recentCandidates[key] = now
            while (recentCandidates.size > MAX_RECENT_CANDIDATES) {
                recentCandidates.remove(recentCandidates.keys.first())
            }
        }

        scope.launch {
            repository.check(RiskCheckRequest(message = text))
                .onSuccess { result ->
                    NotificationMonitorPreferences.recordBackendState(this@FraudNotificationListener, true)
                    if (result.verdict != "Safe") {
                        RiskWarningNotifications.show(this@FraudNotificationListener, result, text.take(1000))
                    }
                }
                .onFailure {
                    NotificationMonitorPreferences.recordBackendState(this@FraudNotificationListener, false)
                }
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private companion object {
        const val DEDUP_WINDOW_MS = 2 * 60 * 1000L
        const val MAX_RECENT_CANDIDATES = 250
        private val paymentContextPattern = Regex(
            "(?iu)(\\bupi\\b|\\bpayment\\b|\\bpayee\\b|\\bpay\\s+(?:now|via|using|to)\\b|" +
                "\\bpaid\\s+(?:₹|rs\\.?|inr|to|for|via)\\b|\\bcollect\\s+request\\b|" +
                "\\btransaction\\b|\\btransfers?\\b|\\bdebit(?:ed)?\\b|\\bcredit(?:ed)?\\b|" +
                "\\brefund\\b|\\bcashback\\b|\\b(?:inr|rs\\.?)\\s*\\d|₹\\s*\\d|" +
                "\\b(?:send|sent|receive|received|transfer|transferred)\\s+(?:you\\s+)?(?:money|funds)\\b|" +
                "\\b(?:money|funds)\\s+(?:sent|received|transferred)\\b|\\b(?:paisa|paise|rupaye|rupees)\\b|" +
                "यूपीआई|भुगतान|पेमेंट|पैसे|पैसा|रुपये|रकम|बँक व्यवहार|बँक खाते|" +
                "बैंक भुगतान|बैंक खाते|पैसे भेज|पैसे जमा|पैसे कट|बँक ट्रान्सफर|" +
                "টাকা পাঠ|টাকা জমা|பணம் அனுப்பு|பணம் பரிமாற்றம்|డబ్బు పంప|ಹಣ ವರ್ಗಾವಣೆ|" +
                "પૈસા મોકલ|પૈસા ટ્રાન્સફર|ਪੈਸੇ ਭੇਜ|ਪੈਸੇ ਟ੍ਰਾਂਸਫਰ)",
        )
        private val financialAccountPattern = Regex(
            "(?iu)(\\bbank\\b|\\bwallet\\b|\\bbank account\\b|\\bkhata\\b|\\bkhate\\b|" +
                "बैंक|बँक|खाता|खाते|வங்கி|బ్యాంక్|ಬ್ಯಾಂಕ್|બેંક|ബാങ്ക്|ব্যাংক|ਬੈਂਕ)",
        )
        private val accountScamActionPattern = Regex(
            "(?iu)(\\botp\\b|\\bpin\\b|\\bkyc\\b|\\bblock(?:ed)?\\b|\\bsuspended\\b|" +
                "\\bverify\\b|\\bshare\\b|\\bsend\\b|\\bclick\\b|\\bupdate\\b|" +
                "ओटीपी|केवाईसी|पिन|ब्लॉक|बंद|शेयर|भेज|तात्काळ|ताबडतोब|" +
                "ओटिपी|पिन|केवायसी|ब्लॉक|पाठवा|शेअर|ஓடிபி|ఓటీపీ|ಒಟಿಪಿ|ઓટીપી|ਓਟੀਪੀ)",
        )

        fun isPaymentRelated(text: String): Boolean =
            paymentContextPattern.containsMatchIn(text) ||
                (financialAccountPattern.containsMatchIn(text) && accountScamActionPattern.containsMatchIn(text))


    }
}
