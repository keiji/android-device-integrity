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
    val encryptedData: String, // Base64URL-encoded, no padding

    @SerialName("client_public_key")
    val clientPublicKey: String, // Standard Base64-encoded

    @SerialName("salt")
    val salt: String, // Base64URL-encoded, no padding

    @SerialName("device_info")
    val deviceInfo: DeviceInfo? = null,

    @SerialName("security_info")
    val securityInfo: SecurityInfo? = null,
)
