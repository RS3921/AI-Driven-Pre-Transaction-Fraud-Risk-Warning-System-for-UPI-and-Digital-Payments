package com.upifraudguard.app.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val SafeGreen = Color(0xFF2E7D32)
private val SuspiciousAmber = Color(0xFFB8860B)
private val HighRiskRed = Color(0xFFC62828)
private val Primary = Color(0xFF1B5E20)

private val LightColors = lightColorScheme(primary = Primary)
private val DarkColors = darkColorScheme(primary = Primary)

/** Verdict colors, shared across screens that show a risk verdict. */
object VerdictColors {
    fun forVerdict(verdict: String): Color = when (verdict) {
        "Safe" -> SafeGreen
        "Suspicious" -> SuspiciousAmber
        "High Risk" -> HighRiskRed
        else -> Color.Gray
    }
}

@Composable
fun UpiFraudGuardTheme(content: @Composable () -> Unit) {
    val colors = if (isSystemInDarkTheme()) DarkColors else LightColors
    MaterialTheme(colorScheme = colors, content = content)
}
