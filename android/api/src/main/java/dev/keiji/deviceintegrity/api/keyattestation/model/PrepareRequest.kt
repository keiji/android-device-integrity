package dev.keiji.deviceintegrity.api.keyattestation.model

import kotlinx.serialization.Serializable

@Serializable
data class PrepareRequest(
    val sessionId: String
)
