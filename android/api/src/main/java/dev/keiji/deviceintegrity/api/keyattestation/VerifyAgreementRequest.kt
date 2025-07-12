package dev.keiji.deviceintegrity.api.keyattestation

import dev.keiji.deviceintegrity.api.DeviceInfo
import dev.keiji.deviceintegrity.api.SecurityInfo
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class VerifyAgreementRequest(
    @SerialName("session_id")
    val sessionId: String,

    @SerialName("encrypted_data")
    val encryptedDataBase64UrlEncoded: String,

    @SerialName("salt")
    val saltBase64UrlEncoded: String,

    @SerialName("certificate_chain")
    val certificateChainBase64Encoded: List<String>,

    @SerialName("device_info")
    val deviceInfo: DeviceInfo,

    @SerialName("security_info")
    val securityInfo: SecurityInfo,
)
