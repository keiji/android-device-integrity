package dev.keiji.deviceintegrity.api.keyattestation.model

import kotlinx.serialization.Serializable

@Serializable
data class PrepareResponse(
    val nonceBase64UrlEncoded: String, // Base64URL Encoded
    val challengeBase64UrlEncoded: String // Base64URL Encoded
)
