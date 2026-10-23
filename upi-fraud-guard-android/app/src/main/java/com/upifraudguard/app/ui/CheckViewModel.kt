package com.upifraudguard.app.ui

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.upifraudguard.app.data.HistoryItem
import com.upifraudguard.app.data.RiskCheckRequest
import com.upifraudguard.app.data.RiskCheckResponse
import com.upifraudguard.app.data.RiskRepository
import kotlinx.coroutines.launch

sealed interface CheckUiState {
    data object Idle : CheckUiState
    data object Loading : CheckUiState
    data class Success(val result: RiskCheckResponse) : CheckUiState
    data class Error(val message: String) : CheckUiState
}

class CheckViewModel(private val repository: RiskRepository = RiskRepository()) : ViewModel() {

    var uiState: CheckUiState by mutableStateOf(CheckUiState.Idle)
        private set

    var history: List<HistoryItem> by mutableStateOf(emptyList())
        private set

    var isHistoryLoading: Boolean by mutableStateOf(false)
        private set

    var historyError: String? by mutableStateOf(null)
        private set

    fun runCheck(
        message: String,
        urlOrQr: String,
        amountText: String,
        recipient: String,
        isNewRecipient: Boolean?,
    ) {
        val amount = amountText.toDoubleOrNull()
        uiState = CheckUiState.Loading
        viewModelScope.launch {
            val request = RiskCheckRequest(
                message = message,
                urlOrQr = urlOrQr,
                amount = amount,
                recipient = recipient,
                isNewRecipient = isNewRecipient,
            )
            repository.check(request).fold(
                onSuccess = { uiState = CheckUiState.Success(it) },
                onFailure = { uiState = CheckUiState.Error(it.message ?: "Something went wrong") },
            )
        }
    }

    fun loadHistory() {
        viewModelScope.launch {
            isHistoryLoading = true
            historyError = null
            repository.history().fold(
                onSuccess = { history = it },
                onFailure = { historyError = it.message ?: "Couldn't load risk history." },
            )
            isHistoryLoading = false
        }
    }

    fun reset() {
        uiState = CheckUiState.Idle
    }
}
