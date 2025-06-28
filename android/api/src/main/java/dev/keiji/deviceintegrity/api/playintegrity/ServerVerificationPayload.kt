package dev.keiji.deviceintegrity.api.playintegrity

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class ServerVerificationPayload(
    @SerialName("device_info") val deviceInfo: DeviceInfo,
    @SerialName("play_integrity_response") val playIntegrityResponse: PlayIntegrityResponseWrapper,
    @SerialName("security_info") val securityInfo: SecurityInfo
) {
    companion object {
        private val json = Json { ignoreUnknownKeys = true } // Configure as needed

        fun fromJson(jsonString: String): ServerVerificationPayload {
            return json.decodeFromString(serializer(), jsonString)
        }
    }
}

@Serializable
data class PlayIntegrityResponseWrapper(
    @SerialName("tokenPayloadExternal") val tokenPayloadExternal: TokenPayloadExternal
)
