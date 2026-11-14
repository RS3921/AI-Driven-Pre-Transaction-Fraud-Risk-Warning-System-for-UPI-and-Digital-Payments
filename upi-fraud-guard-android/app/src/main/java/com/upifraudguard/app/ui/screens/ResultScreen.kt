package com.upifraudguard.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.upifraudguard.app.data.RiskCheckResponse
import com.upifraudguard.app.ui.CheckUiState
import com.upifraudguard.app.ui.CheckViewModel

/**
 * Shows the verdict plain and first -- Safe / Suspicious / High Risk -- with
 * the reasons underneath, before the user goes on to pay.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ResultScreen(viewModel: CheckViewModel, onBack: () -> Unit) {
    val result = viewModel.currentResult ?: (viewModel.uiState as? CheckUiState.Success)?.result

    Scaffold(
        topBar = { TopAppBar(title = { Text("Result") }) },
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState())
                .fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (result == null) {
                Text("No result yet -- run a check first.")
            } else {
                VerdictCard(result)

                // QR Genuine Payment Validation Banner
                result.upiQrDetails?.let { qr ->
                    val isUpiScheme = qr.payeeVpa != null || qr.wellFormed
                    val isWellFormed = qr.wellFormed

                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = if (isUpiScheme && isWellFormed) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.errorContainer,
                        ),
                    ) {
                        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    imageVector = if (isUpiScheme && isWellFormed) Icons.Default.CheckCircle else Icons.Default.Warning,
                                    contentDescription = null,
                                    tint = if (isUpiScheme && isWellFormed) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onErrorContainer,
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = if (isUpiScheme && isWellFormed) "Genuine UPI Payment QR Code" else if (isUpiScheme) "UPI QR Code with Format Warnings" else "Non-UPI / Unrecognized QR Payload",
                                    fontWeight = FontWeight.Bold,
                                    color = if (isUpiScheme && isWellFormed) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onErrorContainer,
                                )
                            }
                            Text(
                                text = if (isUpiScheme && isWellFormed)
                                    "Scanned QR matches standard UPI payment specification (upi://pay...)."
                                else if (isUpiScheme)
                                    "Scanned QR contains a UPI scheme but has missing or unusual parameter flags."
                                else
                                    "Caution: The scanned QR code does not match standard UPI payment specifications (upi://pay...). Confirm recipient details before transferring.",
                                style = MaterialTheme.typography.bodySmall,
                                color = if (isUpiScheme && isWellFormed) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onErrorContainer,
                            )
                        }
                    }
                }

                result.upiQrDetails?.let { qr ->
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            Text("QR payment details", fontWeight = FontWeight.Bold)
                            Text("Payee name: ${qr.payeeName ?: "Not supplied by QR"}")
                            Text("Payee UPI ID: ${qr.payeeVpa ?: "Missing"}")
                            Text(
                                "Amount: ${qr.amount?.let { amount -> "${qr.currency ?: "INR"} $amount" } ?: "Not fixed in QR"}${if (qr.currencyAssumed) " (currency assumed)" else ""}",
                            )
                            qr.transactionNote?.takeIf(String::isNotBlank)?.let { Text("Payment note: $it") }
                            qr.flags.forEach { flag -> Text("Check: $flag") }
                            qr.notices.forEach { notice -> Text("Note: $notice") }
                            Text(
                                "This scan reads the QR fields; it does not verify who owns the UPI ID. Before paying, compare the displayed name and ID with the recipient shown in your payment app.",
                                fontWeight = FontWeight.Medium,
                            )
                        }
                    }
                }

                if (!result.verdict.equals("Safe", ignoreCase = true)) {
                    val actionableReasons = result.reasons.filterNot { reason ->
                        reason.startsWith("UPI ID format recognized", ignoreCase = true) ||
                            reason.startsWith("An amount or recipient ID alone", ignoreCase = true) ||
                            reason.startsWith("UPI payment request QR decoded", ignoreCase = true)
                    }
                    Text("Why this was flagged", fontWeight = FontWeight.Bold)
                    if (actionableReasons.isEmpty()) {
                        Text("The combined score crossed the warning threshold. Review the entered details before paying.")
                    } else {
                        actionableReasons.forEach { reason -> Text("•  $reason") }
                    }
                }

                result.moduleScores?.let { scores ->
                    Text("Module scores", fontWeight = FontWeight.Bold)
                    scores.message?.let { Text("Message: ${"%.0f".format(it * 100)}% risk") }
                    scores.urlQr?.let { Text("Link / QR: ${"%.0f".format(it * 100)}% risk") }
                    scores.transaction?.let { Text("Transaction: ${"%.0f".format(it * 100)}% risk") }
                }

                Text(
                    "This is a decision-support check, not a block -- it doesn't stop or approve a real payment. Use your own judgement, especially for a High Risk result.",
                )
            }

            Button(onClick = { viewModel.reset(); onBack() }, modifier = Modifier.fillMaxWidth()) {
                Text("Run another check")
            }
        }
    }
}

@Composable
private fun VerdictCard(result: RiskCheckResponse) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(result.verdict, fontWeight = FontWeight.Bold)
            Text("Risk score: ${"%.0f".format(result.riskScore * 100)}%")
        }
    }
}
