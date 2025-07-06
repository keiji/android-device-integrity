package dev.keiji.deviceintegrity.api.keyattestation

import kotlinx.serialization.Serializable

@Serializable
data class PrepareRequest(
    val sessionId: String
)
