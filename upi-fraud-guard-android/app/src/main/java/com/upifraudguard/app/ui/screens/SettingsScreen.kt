package com.upifraudguard.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.upifraudguard.app.data.BackendUrlStore
import com.upifraudguard.app.data.ApiTokenStore
import com.upifraudguard.app.data.RiskRepository
import com.upifraudguard.app.notifications.NotificationMonitorPreferences
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var backendUrl by remember { mutableStateOf(BackendUrlStore.get(context)) }
    var apiToken by remember { mutableStateOf(ApiTokenStore.get(context)) }
    var statusMessage by remember { mutableStateOf<String?>(null) }
    var isError by remember { mutableStateOf(false) }
    var isChecking by remember { mutableStateOf(false) }
    var monitorSettings by remember { mutableStateOf(NotificationMonitorPreferences.read(context)) }
    var backgroundStatus by remember { mutableStateOf(NotificationMonitorPreferences.backendStateLabel(context)) }
    var showDeleteHistoryDialog by remember { mutableStateOf(false) }

    fun updateMonitorSettings(transform: (NotificationMonitorPreferences.Settings) -> NotificationMonitorPreferences.Settings) {
        NotificationMonitorPreferences.update(context, transform)
        monitorSettings = NotificationMonitorPreferences.read(context)
    }

    fun saveUrl(): Boolean = try {
        backendUrl = BackendUrlStore.save(context, backendUrl)
        ApiTokenStore.save(context, apiToken)
        statusMessage = "Backend address and API token saved securely on this device."
        isError = false
        true
    } catch (error: IllegalArgumentException) {
        statusMessage = error.message ?: "Enter a valid backend address."
        isError = true
        false
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Connection settings") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Text("Backend address")
            OutlinedTextField(
                value = backendUrl,
                onValueChange = { backendUrl = it; statusMessage = null },
                label = { Text("API base URL") },
                placeholder = { Text("https://fraud-api.example.com/") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Text(
                "Emulator: keep http://10.0.2.2:8000/ for local development. For a real phone or any network deployment, use an HTTPS address and a per-user API token issued by the API administrator.",
            )
            OutlinedTextField(
                value = apiToken,
                onValueChange = { apiToken = it; statusMessage = null },
                label = { Text("API access token (if required)") },
                placeholder = { Text("Paste the token issued for your user") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
            )
            Text("This is an API access token, not your email password or Google Authenticator code. It is encrypted with Android Keystore on this device.")
            TextButton(onClick = {
                apiToken = ""
                ApiTokenStore.clear(context)
                statusMessage = "Saved API token removed from this device."
                isError = false
            }) { Text("Remove saved API token") }
            Button(
                onClick = { saveUrl() },
                enabled = !isChecking,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Save address") }
            OutlinedButton(
                onClick = {
                    if (saveUrl()) {
                        isChecking = true
                        statusMessage = "Checking the backend…"
                        scope.launch {
                            RiskRepository(
                                { BackendUrlStore.get(context) },
                                { ApiTokenStore.get(context) },
                            ).status()
                                .fold(
                                    onSuccess = { status ->
                                        statusMessage = "Connected — API ${status.version.ifBlank { "is running" }}."
                                        isError = false
                                        NotificationMonitorPreferences.recordBackendState(context, true)
                                        backgroundStatus = NotificationMonitorPreferences.backendStateLabel(context)
                                    },
                                    onFailure = { error ->
                                        statusMessage = "Couldn't connect: ${error.message ?: "check the address and network"}"
                                        isError = true
                                        NotificationMonitorPreferences.recordBackendState(context, false)
                                        backgroundStatus = NotificationMonitorPreferences.backendStateLabel(context)
                                    },
                                )
                            isChecking = false
                        }
                    }
                },
                enabled = !isChecking,
                modifier = Modifier.fillMaxWidth(),
            ) {
                if (isChecking) CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp))
                Text(if (isChecking) "Testing…" else "Save and test connection")
            }
            statusMessage?.let { message ->
                Text(message, color = if (isError) androidx.compose.material3.MaterialTheme.colorScheme.error else androidx.compose.material3.MaterialTheme.colorScheme.primary)
            }

            Text("Automatic notification checks", style = androidx.compose.material3.MaterialTheme.typography.titleMedium)
            Text("Android Notification Access must also be enabled for background checks to run.")
            MonitorSwitchRow("Enable automatic notification checks", monitorSettings.enabled) { enabled ->
                updateMonitorSettings { current -> current.copy(enabled = enabled) }
            }
            MonitorSwitchRow("Telegram", monitorSettings.telegram, enabled = monitorSettings.enabled) { enabled ->
                updateMonitorSettings { current -> current.copy(telegram = enabled) }
            }
            MonitorSwitchRow("WhatsApp", monitorSettings.whatsapp, enabled = monitorSettings.enabled) { enabled ->
                updateMonitorSettings { current -> current.copy(whatsapp = enabled) }
            }
            MonitorSwitchRow("SMS / Messages", monitorSettings.messages, enabled = monitorSettings.enabled) { enabled ->
                updateMonitorSettings { current -> current.copy(messages = enabled) }
            }
            MonitorSwitchRow("Other apps (payment-keyword matches)", monitorSettings.otherApps, enabled = monitorSettings.enabled) { enabled ->
                updateMonitorSettings { current -> current.copy(otherApps = enabled) }
            }
            Text(
                "Selected apps are filtered before analysis: ordinary chats, generic links, and standalone OTP messages are ignored. Only text matching payment terms or a bank/wallet warning plus a security action is sent to your configured backend. Android only exposes text shown in the notification, not the full chat. An analyzed check is kept in your history for 30 days.",
            )
            Text(
                backgroundStatus,
                color = if (backgroundStatus.startsWith("Backend unreachable")) androidx.compose.material3.MaterialTheme.colorScheme.error else androidx.compose.material3.MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text("Only use HTTP for local emulator development. The API refuses network binding unless per-user authentication and HTTPS are configured.")

            Text("Your stored checks", style = androidx.compose.material3.MaterialTheme.typography.titleMedium)
            Text("Checks are isolated by the API token's user account and automatically removed after 30 days.")
            OutlinedButton(
                onClick = { showDeleteHistoryDialog = true },
                enabled = !isChecking,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Delete my saved history") }
        }
    }

    if (showDeleteHistoryDialog) {
        AlertDialog(
            onDismissRequest = { showDeleteHistoryDialog = false },
            title = { Text("Delete saved history?") },
            text = { Text("This permanently deletes checks belonging to this API user. It cannot be undone.") },
            confirmButton = {
                TextButton(onClick = {
                    showDeleteHistoryDialog = false
                    isChecking = true
                    statusMessage = "Deleting your saved history…"
                    scope.launch {
                        RiskRepository(
                            { BackendUrlStore.get(context) },
                            { ApiTokenStore.get(context) },
                        ).deleteHistory().fold(
                            onSuccess = { count ->
                                statusMessage = "$count saved checks deleted."
                                isError = false
                            },
                            onFailure = { error ->
                                statusMessage = "Couldn't delete history: ${error.message ?: "check the backend connection"}"
                                isError = true
                            },
                        )
                        isChecking = false
                    }
                }) { Text("Delete") }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteHistoryDialog = false }) { Text("Cancel") }
            },
        )
    }
}

@Composable
private fun MonitorSwitchRow(
    title: String,
    checked: Boolean,
    enabled: Boolean = true,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(title, modifier = Modifier.weight(1f).padding(end = 12.dp))
        Switch(checked = checked, onCheckedChange = onCheckedChange, enabled = enabled)
    }
}
