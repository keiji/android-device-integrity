package dev.keiji.deviceintegrity.api.playintegrity

import kotlinx.serialization.Serializable
import retrofit2.http.Body
import retrofit2.http.POST

interface PlayIntegrityTokenVerifyApi {
    @POST("/play-integrity/classic/nonce")
    suspend fun getNonce(@Body request: NonceRequest): NonceResponse

    @POST("/play-integrity/classic/verify")
    suspend fun verifyToken(@Body request: VerifyTokenRequest): VerifyTokenResponse
}

@Serializable
data class NonceRequest(
    val someData: String // 必要に応じてリクエストのパラメータを定義してください
)

@Serializable
data class NonceResponse(
    val nonce: String,
    // TODO: Check actual response field name for TTL or generated_datetime
    val generated_datetime: Long
)

@Serializable
data class VerifyTokenRequest(
    val token: String
)

@Serializable
data class VerifyTokenResponse(
    // TODO: Define based on actual server response for verification
    val status: String
)
