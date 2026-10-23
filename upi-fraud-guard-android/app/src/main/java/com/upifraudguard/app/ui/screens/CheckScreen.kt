package com.upifraudguard.app.ui.screens

import android.content.Intent
import android.os.Build
import android.Manifest
import android.content.pm.PackageManager
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.upifraudguard.app.data.RiskCheckResponse
import com.upifraudguard.app.notifications.RiskWarningNotifications
import com.upifraudguard.app.ui.CheckUiState
import com.upifraudguard.app.ui.CheckViewModel

/**
 * The screen a user opens right before paying: paste the message they got,
 * or a payment link/UPI ID, plus the amount if they have it, and get a
 * plain verdict before switching over to GPay/PhonePe/Paytm to actually pay.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CheckScreen(
    viewModel: CheckViewModel,
    onScanQr: () -> Unit,
    onOpenHistory: () -> Unit,
    onOpenSettings: () -> Unit,
    onResult: () -> Unit,
) {
    val context = LocalContext.current
    var pendingWarning by remember { mutableStateOf<RiskCheckResponse?>(null) }
    val requestWarningPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) pendingWarning?.let { RiskWarningNotifications.show(context, it) }
        if (pendingWarning != null) onResult()
        pendingWarning = null
    }
    val notificationPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) context.startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
    }
    var message by remember { mutableStateOf("") }
    var urlOrQr by remember { mutableStateOf("") }
    var amount by remember { mutableStateOf("") }
    var recipient by remember { mutableStateOf("") }

    val state = viewModel.uiState
    LaunchedEffect(state) {
        if (state is CheckUiState.Success) {
            if (state.result.verdict != "Safe") {
                if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(
                        context,
                        Manifest.permission.POST_NOTIFICATIONS,
                    ) != PackageManager.PERMISSION_GRANTED
                ) {
                    pendingWarning = state.result
                    requestWarningPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
                } else {
                    RiskWarningNotifications.show(context, state.result)
                    onResult()
                }
            } else {
                onResult()
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Check before you pay") },
                actions = {
                    OutlinedButton(onClick = onOpenHistory) { Text("History") }
                    OutlinedButton(onClick = onOpenSettings) {
                        Icon(Icons.Filled.Settings, contentDescription = "Settings")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState())
                .fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("Paste the message, link, or UPI ID you're unsure about. Add the amount if you know it -- none of this is required, check with whatever you have.")

            Text("The model-backed check needs the Python API running, but the website does not need to stay open. To check matching new alerts from other apps, enable Notification access below. Matching alert text is sent to your configured backend and kept in its SQLite history for 30 days. Turn access off any time in Android Settings.")
            OutlinedButton(
                onClick = {
                    if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(
                            context,
                            Manifest.permission.POST_NOTIFICATIONS,
                        ) != PackageManager.PERMISSION_GRANTED
                    ) {
                        notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
                    } else {
                        context.startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Set up automatic notification checks") }

            OutlinedTextField(
                value = message,
                onValueChange = { message = it },
                label = { Text("Message text (SMS / WhatsApp)") },
                modifier = Modifier.fillMaxWidth(),
                minLines = 3,
            )

            OutlinedTextField(
                value = urlOrQr,
                onValueChange = { urlOrQr = it },
                label = { Text("Payment link or UPI ID") },
                modifier = Modifier.fillMaxWidth(),
            )

            OutlinedButton(onClick = onScanQr, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Filled.QrCodeScanner, contentDescription = null)
                Text("  Scan a QR code instead")
            }

            OutlinedTextField(
                value = amount,
                onValueChange = { input -> amount = input.filter { it.isDigit() || it == '.' } },
                label = { Text("Amount (₹, optional)") },
                modifier = Modifier.fillMaxWidth(),
            )
            if (amount.isNotBlank() && amount.toDoubleOrNull() == null) {
                Text("Enter a valid amount, for example 120.50.", color = androidx.compose.material3.MaterialTheme.colorScheme.error)
            }

            OutlinedTextField(
                value = recipient,
                onValueChange = { recipient = it },
                label = { Text("Recipient name / UPI ID (optional)") },
                modifier = Modifier.fillMaxWidth(),
            )

            Button(
                onClick = {
                    viewModel.runCheck(
                        message = message,
                        urlOrQr = urlOrQr,
                        amountText = amount,
                        recipient = recipient,
                        isNewRecipient = null,
                    )
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = state !is CheckUiState.Loading &&
                    (amount.isBlank() || amount.toDoubleOrNull() != null) &&
                    (message.isNotBlank() || urlOrQr.isNotBlank() || amount.toDoubleOrNull() != null),
            ) {
                if (state is CheckUiState.Loading) {
                    CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp))
                }
                Text("Check before paying")
            }

            if (state is CheckUiState.Error) {
                Text("Check failed: ${state.message}. Verify the backend connection; if authentication is required, update the API token in Settings.")
            }
        }
    }
}
