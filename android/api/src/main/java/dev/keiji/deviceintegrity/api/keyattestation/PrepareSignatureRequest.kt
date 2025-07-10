package dev.keiji.deviceintegrity.api.keyattestation

import kotlinx.serialization.Serializable
import kotlinx.serialization.SerialName

@Serializable
data class PrepareSignatureRequest(
    @SerialName("session_id")
    val sessionId: String
)
