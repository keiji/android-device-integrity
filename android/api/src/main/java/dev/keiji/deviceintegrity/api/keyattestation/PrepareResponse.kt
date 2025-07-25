package dev.keiji.deviceintegrity.api.keyattestation

import kotlinx.serialization.Serializable
import kotlinx.serialization.SerialName

@Serializable
data class PrepareResponse(
    @SerialName("session_id")
    val sessionId: String,
    @SerialName("nonce")
    val nonceBase64UrlEncoded: String,
    @SerialName("challenge")
    val challengeBase64UrlEncoded: String
)
