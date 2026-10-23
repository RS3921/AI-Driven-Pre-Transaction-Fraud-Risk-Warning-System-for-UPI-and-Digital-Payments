package com.upifraudguard.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.upifraudguard.app.data.HistoryItem
import com.upifraudguard.app.ui.CheckViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HistoryScreen(viewModel: CheckViewModel, selectedMessage: String? = null) {
    LaunchedEffect(Unit) { viewModel.loadHistory() }
    val selected = viewModel.history.firstOrNull { item ->
        !selectedMessage.isNullOrBlank() && item.message.isNotBlank() &&
            (item.message == selectedMessage || selectedMessage.startsWith(item.message))
    }

    Scaffold(
        topBar = { TopAppBar(title = { Text(if (selected != null) "Alert details" else "Risk history · last 30 days") }) },
    ) { padding ->
        LazyColumn(
            modifier = Modifier.padding(padding).fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            if (viewModel.isHistoryLoading && viewModel.history.isEmpty()) {
                item { CircularProgressIndicator() }
            }
            viewModel.historyError?.let { error ->
                item {
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("Couldn't load history: $error", color = MaterialTheme.colorScheme.error)
                        TextButton(onClick = viewModel::loadHistory) { Text("Try again") }
                    }
                }
            }
            if (selected != null) {
                item { HistoryCard(selected, highlighted = true) }
                item { Text("Other recent checks", fontWeight = FontWeight.Bold) }
            }
            items(viewModel.history.filterNot { it == selected }) { item ->
                HistoryCard(item)
            }
            if (viewModel.history.isEmpty() && !viewModel.isHistoryLoading && viewModel.historyError == null) {
                item { Text("No checks in the last 30 days.") }
            }
        }
    }
}

@Composable
private fun HistoryCard(item: HistoryItem, highlighted: Boolean = false) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
            if (highlighted) Text("Opened from your alert", color = MaterialTheme.colorScheme.primary)
            Text(item.verdict, fontWeight = FontWeight.Bold)
            Text("Risk score: ${"%.0f".format(item.riskScore * 100)}%  ·  ${item.createdAt.replace('T', ' ').take(16)}")
            if (item.message.isNotBlank()) {
                Text("Message", fontWeight = FontWeight.SemiBold)
                Text(item.message)
            }
            if (item.urlOrQr.isNotBlank()) {
                Text("Link / QR", fontWeight = FontWeight.SemiBold)
                Text(item.urlOrQr)
            }
            item.upiQrDetails?.let { qr ->
                Text("Decoded UPI payment details", fontWeight = FontWeight.SemiBold)
                Text("Payee name: ${qr.payeeName ?: "Not supplied by QR"}")
                Text("Payee UPI ID: ${qr.payeeVpa ?: "Missing"}")
                Text(
                    "Amount: ${qr.amount?.let { value -> "${qr.currency ?: "INR"} $value" } ?: "Not fixed in QR"}" +
                        if (qr.currencyAssumed) " (currency assumed)" else "",
                )
                qr.flags.forEach { flag -> Text("Check: $flag") }
                Text("The QR fields do not verify who owns this UPI ID.")
            }
            if (item.amount != null) Text("Amount: ₹${item.amount}")
            if (item.recipient.isNotBlank()) Text("Recipient: ${item.recipient}")
            if (item.reasons.isNotEmpty()) {
                Text("Why it was flagged", fontWeight = FontWeight.SemiBold)
                item.reasons.forEach { reason -> Text("• $reason") }
            }
        }
    }
}
