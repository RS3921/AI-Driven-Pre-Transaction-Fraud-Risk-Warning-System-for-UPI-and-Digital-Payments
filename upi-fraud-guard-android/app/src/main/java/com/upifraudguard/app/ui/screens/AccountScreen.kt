package com.upifraudguard.app.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.util.Patterns
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.upifraudguard.app.data.LocalProfileStore
import com.upifraudguard.app.data.TotpAuthenticator

@OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)
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
            modifier = Modifier.padding(padding).fillMaxSize().padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Text("Set up a profile to continue to UPI Fraud Guard.", style = MaterialTheme.typography.titleMedium)
            OutlinedTextField(value = name, onValueChange = { name = it; message = null }, label = { Text("Your name") }, singleLine = true, modifier = Modifier.fillMaxWidth(), enabled = secret == null)
            OutlinedTextField(value = email, onValueChange = { email = it; message = null }, label = { Text("Email address") }, singleLine = true, modifier = Modifier.fillMaxWidth(), enabled = secret == null)

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
                Text("Add this setup key in Google Authenticator", fontWeight = FontWeight.Bold)
                Text("In Google Authenticator, tap + → Enter a setup key. Use your email as the account name, paste the key below, and choose Time based.")
                Text(secret!!, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                OutlinedButton(
                    onClick = {
                        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        clipboard.setPrimaryClip(ClipData.newPlainText("UPI Fraud Guard setup key", secret!!))
                        message = "Setup key copied. Treat it like a password."
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
                                .onFailure { message = "Could not save the local profile: ${it.message ?: "try again"}" }
                        } else message = "That code did not match. Check the setup key and enter the current code."
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
