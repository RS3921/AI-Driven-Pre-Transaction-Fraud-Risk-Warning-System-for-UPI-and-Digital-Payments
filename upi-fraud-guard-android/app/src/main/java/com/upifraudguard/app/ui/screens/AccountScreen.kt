package com.upifraudguard.app.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.util.Patterns
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.upifraudguard.app.data.LocalProfileStore
import com.upifraudguard.app.data.TotpAuthenticator
import com.upifraudguard.app.ui.QrCodeGenerator

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AccountScreen(onAccountCreated: () -> Unit) {
    val context = LocalContext.current
    var name by remember { mutableStateOf("") }
    var email by remember { mutableStateOf("") }
    var secret by remember { mutableStateOf<String?>(null) }
    var code by remember { mutableStateOf("") }
    var message by remember { mutableStateOf<String?>(null) }

    Scaffold(topBar = { TopAppBar(title = { Text("Create your account") }) }) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Text("Set up a profile to continue to UPI Fraud Guard.", style = MaterialTheme.typography.titleMedium)
            OutlinedTextField(
                value = name,
                onValueChange = { name = it; message = null },
                label = { Text("Your name") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                enabled = secret == null,
            )
            OutlinedTextField(
                value = email,
                onValueChange = { email = it; message = null },
                label = { Text("Email address") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                enabled = secret == null,
            )

            if (secret == null) {
                Text("Verification uses a six-digit code from Google Authenticator. This app will not email you a code.", style = MaterialTheme.typography.bodySmall)
                Button(
                    onClick = {
                        when {
                            name.isBlank() -> message = "Enter your name."
                            !Patterns.EMAIL_ADDRESS.matcher(email.trim()).matches() -> message = "Enter a valid email address."
                            else -> { secret = TotpAuthenticator.newSecret(); message = null }
                        }
                    },
                    enabled = name.isNotBlank() && email.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Continue to authenticator setup") }
            } else {
                Text("Scan QR Code or Enter Setup Key", fontWeight = FontWeight.Bold, style = MaterialTheme.typography.titleMedium)
                Text("Open Google Authenticator → tap + → Scan a QR code, or choose Enter a setup key.")

                // QR Code Image
                val provisioningUri = remember(secret, email) {
                    TotpAuthenticator.provisioningUri(secret!!, email)
                }
                val qrBitmap = remember(provisioningUri) {
                    QrCodeGenerator.generateQrBitmap(provisioningUri, 400)
                }

                if (qrBitmap != null) {
                    Card(
                        modifier = Modifier.align(Alignment.CenterHorizontally),
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        elevation = CardDefaults.cardElevation(defaultElevation = 4.dp),
                    ) {
                        Box(
                            modifier = Modifier.padding(16.dp),
                            contentAlignment = Alignment.Center,
                        ) {
                            Image(
                                bitmap = qrBitmap.asImageBitmap(),
                                contentDescription = "2FA Authenticator Setup QR Code",
                                modifier = Modifier.size(200.dp),
                            )
                        }
                    }
                }

                Text("Manual setup key:", fontWeight = FontWeight.SemiBold)
                Text(secret!!, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                OutlinedButton(
                    onClick = {
                        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        clipboard.setPrimaryClip(ClipData.newPlainText("UPI Fraud Guard setup key", secret!!))
                        message = "Setup key copied to clipboard."
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Copy setup key") }

                OutlinedTextField(
                    value = code,
                    onValueChange = { code = it.filter(Char::isDigit).take(6); message = null },
                    label = { Text("6-digit authenticator code") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Text("Codes change every 30 seconds. The secret stays on this phone and is encrypted with Android Keystore.", style = MaterialTheme.typography.bodySmall)

                Button(
                    onClick = {
                        if (TotpAuthenticator.verify(secret!!, code)) {
                            runCatching { LocalProfileStore.save(context, name, email, secret!!) }
                                .onSuccess { onAccountCreated() }
                                .onFailure { message = "Could not save profile: ${it.message ?: "try again"}" }
                        } else message = "That code did not match. Check the setup key/QR code and enter the current code."
                    },
                    enabled = code.length == 6,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Verify code and create profile") }

                OutlinedButton(onClick = { secret = null; code = ""; message = null }, modifier = Modifier.fillMaxWidth()) { Text("Back") }
            }

            message?.let { Text(it, color = if (it.startsWith("That code") || it.startsWith("Could not")) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary) }
            Text("This is a local prototype profile, not an online account and not proof that you own the email address.", style = MaterialTheme.typography.bodySmall)
        }
    }
}
