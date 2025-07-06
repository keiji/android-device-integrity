package dev.keiji.deviceintegrity.api.keyattestation.model

import kotlinx.serialization.Serializable

@Serializable
data class PrepareRequestBody(
    val sessionId: String
)
