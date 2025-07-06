package dev.keiji.deviceintegrity.api.keyattestation.model

import kotlinx.serialization.Serializable

@Serializable
data class PrepareResponseBody(
    val nonce: String, // Base64URL Encoded
    val challenge: String // Base64URL Encoded
)
