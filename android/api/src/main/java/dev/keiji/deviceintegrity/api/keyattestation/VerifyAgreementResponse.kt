package dev.keiji.deviceintegrity.api.keyattestation

import dev.keiji.deviceintegrity.api.DeviceInfo
import dev.keiji.deviceintegrity.api.SecurityInfo
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class VerifyAgreementResponse(
    @SerialName("session_id")
    val sessionId: String,

    @SerialName("is_verified")
    val isVerified: Boolean,

    @SerialName("reason")
    val reason: String? = null, // reason can still be optional

    @SerialName("attestation_info")
    val attestationInfo: AttestationInfo,

    @SerialName("device_info")
    val deviceInfo: DeviceInfo,

    @SerialName("security_info")
    val securityInfo: SecurityInfo,

    @SerialName("certificate_chain")
    val certificateChain: List<CertificateDetails> = emptyList()
)
