package dev.keiji.deviceintegrity.api.keyattestation

import kotlinx.serialization.Serializable

@Serializable
data class VerifyEcRequest(
    val sessionId: String,
    val signedDataBase64UrlEncoded: String, // Base64URL Encoded
    val nonceBBase64UrlEncoded: String, // Base64URL Encoded
    val certificateChainBase64UrlEncoded: List<String> // List of Base64URL Encoded strings
)
