package com.upifraudguard.app.data

import com.google.gson.annotations.SerializedName

/**
 * Mirrors the backend's RiskCheckRequest (api/main.py). Every field is
 * optional there, so we only send what the user actually filled in.
 */
data class RiskCheckRequest(
    val message: String = "",
    @SerializedName("url_or_qr") val urlOrQr: String = "",
    val amount: Double? = null,
    val recipient: String = "",
    @SerializedName("payments_last_hour") val paymentsLastHour: Int? = null,
    @SerializedName("is_new_recipient") val isNewRecipient: Boolean? = null,
)

data class ShapFeature(
    val feature: String,
    val label: String,
    val contribution: Double,
    val direction: String, // "increased_risk" | "decreased_risk"
)

data class ShapExplanations(
    val message: List<ShapFeature> = emptyList(),
    @SerializedName("url_qr") val urlQr: List<ShapFeature> = emptyList(),
    val transaction: List<ShapFeature> = emptyList(),
)

data class ModuleScores(
    val message: Double?,
    @SerializedName("url_qr") val urlQr: Double?,
    val transaction: Double?,
)

/** Mirrors the JSON returned by POST /check (and /check-message). */
data class RiskCheckResponse(
    val verdict: String, // "Safe" | "Suspicious" | "High Risk"
    @SerializedName("risk_score") val riskScore: Double,
    val reasons: List<String> = emptyList(),
    @SerializedName("modules_used") val modulesUsed: List<String> = emptyList(),
    @SerializedName("module_scores") val moduleScores: ModuleScores? = null,
    @SerializedName("shap_explanations") val shapExplanations: ShapExplanations? = null,
    @SerializedName("upi_qr_details") val upiQrDetails: UpiQrDetails? = null,
)

/** Parsed UPI payment fields. These details are decoded from the QR, not verified against a bank. */
data class UpiQrDetails(
    @SerializedName("payee_vpa") val payeeVpa: String? = null,
    @SerializedName("payee_name") val payeeName: String? = null,
    val amount: String? = null,
    val currency: String? = null,
    @SerializedName("currency_assumed") val currencyAssumed: Boolean = false,
    @SerializedName("merchant_code") val merchantCode: String? = null,
    @SerializedName("transaction_note") val transactionNote: String? = null,
    @SerializedName("reference_id") val referenceId: String? = null,
    val flags: List<String> = emptyList(),
    @SerializedName("well_formed") val wellFormed: Boolean = false,
)

/** Mirrors one row from GET /history. */
data class HistoryItem(
    @SerializedName("created_at") val createdAt: String,
    val verdict: String,
    @SerializedName("risk_score") val riskScore: Double,
    val reasons: List<String> = emptyList(),
    val message: String = "",
    @SerializedName("url_or_qr") val urlOrQr: String = "",
    val amount: Double? = null,
    val recipient: String = "",
    @SerializedName("upi_qr_details") val upiQrDetails: UpiQrDetails? = null,
)

/** Mirrors the payload returned by POST /scan-qr. */
data class QrScanResponse(
    val payload: String,
    val kind: String,
    @SerializedName("risk_score") val riskScore: Double?,
    val reasons: List<String> = emptyList(),
    @SerializedName("upi_qr_details") val upiQrDetails: UpiQrDetails? = null,
)

/** Health response from GET /status. */
data class BackendStatus(
    val status: String,
    val version: String = "",
    @SerializedName("authentication_required") val authenticationRequired: Boolean = false,
)

data class BackendSession(
    @SerializedName("user_id") val userId: String,
    val authenticated: Boolean,
)

data class HistoryDeletion(
    @SerializedName("deleted_count") val deletedCount: Int,
)
