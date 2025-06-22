package dev.keiji.deviceintegrity.api.playintegrity

import kotlinx.serialization.Serializable
import retrofit2.http.Body
import retrofit2.http.POST

interface PlayIntegrityTokenVerifyApi {
    @POST("/play-integrity/nonce")
    suspend fun getNonce(@Body request: NonceRequest): NonceResponse
}

@Serializable
data class NonceRequest(
    val someData: String // 必要に応じてリクエストのパラメータを定義してください
)

@Serializable
data class NonceResponse(
    val nonce: String,
    val ttl: Long
)
