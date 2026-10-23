package com.upifraudguard.app.data

import okhttp3.MultipartBody
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Multipart
import retrofit2.http.POST
import retrofit2.http.Part
import retrofit2.http.Query

/** Talks to the existing FastAPI backend in api/main.py -- no new endpoints needed. */
interface RiskGuardApi {

    @GET("status")
    suspend fun status(): Response<BackendStatus>

    @GET("session")
    suspend fun session(): Response<BackendSession>

    @POST("check")
    suspend fun check(@Body request: RiskCheckRequest): Response<RiskCheckResponse>

    @Multipart
    @POST("scan-qr")
    suspend fun scanQr(@Part image: MultipartBody.Part): Response<QrScanResponse>

    @GET("history")
    suspend fun history(
        @Query("limit") limit: Int = 5000,
    ): Response<List<HistoryItem>>

    @DELETE("history")
    suspend fun deleteHistory(): Response<HistoryDeletion>
}
