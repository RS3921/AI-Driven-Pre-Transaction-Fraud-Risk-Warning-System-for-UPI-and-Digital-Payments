package com.upifraudguard.app.data

import com.upifraudguard.app.BuildConfig
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit

/**
 * Thin wrapper around RiskGuardApi. Kept separate from the ViewModel so the
 * network layer can be swapped or mocked (e.g. for tests, or later for an
 * offline-first cache) without touching the UI.
 */
class RiskRepository(
    private val baseUrlProvider: () -> String = { BuildConfig.API_BASE_URL },
    private val tokenProvider: () -> String = { "" },
) {

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .addInterceptor { chain ->
            val token = tokenProvider().trim()
            val request = chain.request().newBuilder().apply {
                if (token.isNotEmpty()) header("Authorization", "Bearer $token")
            }.build()
            chain.proceed(request)
        }
        .addInterceptor(HttpLoggingInterceptor().apply { level = HttpLoggingInterceptor.Level.BASIC })
        .build()

    @Volatile private var cachedBaseUrl: String? = null
    @Volatile private var cachedApi: RiskGuardApi? = null

    private fun api(): RiskGuardApi {
        val baseUrl = baseUrlProvider()
        cachedApi?.let { if (cachedBaseUrl == baseUrl) return it }
        return synchronized(this) {
            cachedApi?.takeIf { cachedBaseUrl == baseUrl } ?: Retrofit.Builder()
                .baseUrl(baseUrl)
                .client(client)
                .addConverterFactory(GsonConverterFactory.create())
                .build()
                .create(RiskGuardApi::class.java)
                .also {
                    cachedBaseUrl = baseUrl
                    cachedApi = it
                }
        }
    }

    suspend fun status(): Result<BackendStatus> = runCatching {
        val response = api().status()
        if (!response.isSuccessful) error("Server returned HTTP ${response.code()}")
        val body = response.body() ?: error("The server returned an empty status response")
        if (body.status != "running") error("The server responded, but it isn't reporting a running status")
        if (body.authenticationRequired) {
            val sessionResponse = api().session()
            if (sessionResponse.code() == 401) error("Authentication required. Enter the API token issued for this user in Settings.")
            if (!sessionResponse.isSuccessful) error("Could not validate the API token (HTTP ${sessionResponse.code()})")
        }
        body
    }

    suspend fun check(request: RiskCheckRequest): Result<RiskCheckResponse> = runCatching {
        val response = api().check(request)
        if (response.code() == 401) error("Authentication required. Check the API token in Settings.")
        if (!response.isSuccessful) error("Server error ${response.code()}: ${response.errorBody()?.string()}")
        response.body() ?: error("Empty response from server")
    }

    suspend fun history(limit: Int = 5000): Result<List<HistoryItem>> = runCatching {
        val response = api().history(limit)
        if (response.code() == 401) error("Authentication required. Check the API token in Settings.")
        if (!response.isSuccessful) error("Server error ${response.code()}")
        response.body() ?: emptyList()
    }

    suspend fun deleteHistory(): Result<Int> = runCatching {
        val response = api().deleteHistory()
        if (response.code() == 401) error("Authentication required. Check the API token in Settings.")
        if (!response.isSuccessful) error("Server error ${response.code()}")
        response.body()?.deletedCount ?: 0
    }
}
