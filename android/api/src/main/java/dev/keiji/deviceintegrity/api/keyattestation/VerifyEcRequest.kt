package dev.keiji.deviceintegrity.api.keyattestation

import dev.keiji.deviceintegrity.api.DeviceInfo
import dev.keiji.deviceintegrity.api.SecurityInfo
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerialName

@Serializable
data class VerifyEcRequest(
    @SerialName("session_id")
    val sessionId: String,
    @SerialName("signature")
    val signatureDataBase64UrlEncoded: String, // Assuming signature and nonce_b remain Base64URL encoded as per existing server code and OpenAPI spec for these fields
    @SerialName("nonce_b")
    val nonceBBase64UrlEncoded: String,
    @SerialName("certificate_chain")
    val certificateChainBase64Encoded: List<String>,
    @SerialName("device_info")
    val deviceInfo: DeviceInfo? = null,
    @SerialName("security_info")
    val securityInfo: SecurityInfo? = null
)
