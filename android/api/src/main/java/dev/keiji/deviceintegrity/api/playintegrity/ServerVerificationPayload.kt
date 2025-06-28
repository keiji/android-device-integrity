package dev.keiji.deviceintegrity.api.playintegrity

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ServerVerificationPayload(
    @SerialName("device_info") val deviceInfo: DeviceInfo,
    @SerialName("play_integrity_response") val playIntegrityResponse: PlayIntegrityResponseWrapper,
    @SerialName("security_info") val securityInfo: SecurityInfo
)
// Companion object and fromJson method removed

@Serializable
data class PlayIntegrityResponseWrapper(
    @SerialName("tokenPayloadExternal") val tokenPayloadExternal: TokenPayloadExternal
)
