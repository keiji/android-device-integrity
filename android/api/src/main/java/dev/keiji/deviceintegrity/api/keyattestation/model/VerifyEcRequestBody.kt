package dev.keiji.deviceintegrity.api.keyattestation.model

import kotlinx.serialization.Serializable

@Serializable
data class VerifyEcRequestBody(
    val sessionId: String,
    val signedData: String, // Base64 Encoded
    val nonceB: String, // Base64 Encoded
    val certificateChain: List<String> // List of Base64 Encoded strings
)
