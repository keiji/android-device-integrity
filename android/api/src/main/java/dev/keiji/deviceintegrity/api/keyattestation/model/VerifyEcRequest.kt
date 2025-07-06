package dev.keiji.deviceintegrity.api.keyattestation.model

import kotlinx.serialization.Serializable

@Serializable
data class VerifyEcRequest(
    val sessionId: String,
    val signedDataBase64Encoded: String, // Base64 Encoded
    val nonceBBase64Encoded: String, // Base64 Encoded
    val certificateChainBase64Encoded: List<String> // List of Base64 Encoded strings
)
