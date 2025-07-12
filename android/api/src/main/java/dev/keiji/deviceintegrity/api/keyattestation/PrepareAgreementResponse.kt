package dev.keiji.deviceintegrity.api.keyattestation

import kotlinx.serialization.Serializable
import kotlinx.serialization.SerialName

@Serializable
data class PrepareAgreementResponse(
    @SerialName("nonce")
    val nonceBase64UrlEncoded: String,
    @SerialName("challenge")
    val challengeBase64UrlEncoded: String,
    @SerialName("public_key")
    val publicKeyBase64UrlEncoded: String
)
