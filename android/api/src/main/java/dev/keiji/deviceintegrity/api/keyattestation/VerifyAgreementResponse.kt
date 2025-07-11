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

    @SerialName("attestation_info")
    val attestationInfo: AttestationInfo? = null,

    @SerialName("device_info")
    val deviceInfo: dev.keiji.deviceintegrity.api.DeviceInfo? = null,

    @SerialName("security_info")
    val securityInfo: dev.keiji.deviceintegrity.api.SecurityInfo? = null,
)
