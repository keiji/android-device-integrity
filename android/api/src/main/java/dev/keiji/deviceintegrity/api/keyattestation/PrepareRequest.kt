package dev.keiji.deviceintegrity.api.keyattestation // Changed package

import kotlinx.serialization.Serializable

@Serializable
data class PrepareRequest(
    val sessionId: String
)
