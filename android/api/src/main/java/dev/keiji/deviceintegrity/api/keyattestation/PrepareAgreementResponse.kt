package dev.keiji.deviceintegrity.api.keyattestation

import kotlinx.serialization.Serializable
import kotlinx.serialization.SerialName

@Serializable
data class PrepareAgreementResponse(
    @SerialName("salt")
    val saltBase64UrlEncoded: String,
    @SerialName("challenge")
    val challengeBase64UrlEncoded: String
)
