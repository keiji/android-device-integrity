package dev.keiji.deviceintegrity.api.keyattestation

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class VerifyAgreementResponse(
    @SerialName("session_id")
    val sessionId: String,

    @SerialName("is_verified")
    val isVerified: Boolean,

    @SerialName("reason")
    val reason: String? = null,
)
