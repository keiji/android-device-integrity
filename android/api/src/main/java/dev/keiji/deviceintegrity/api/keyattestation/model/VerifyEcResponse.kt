package dev.keiji.deviceintegrity.api.keyattestation.model

import kotlinx.serialization.Serializable

@Serializable
data class DecodedCertificateChainMock(
    val mockedDetail: String
)

@Serializable
data class AttestationPropertiesMock(
    val mockedSoftwareEnforced: Map<String, String>, // Assuming simple key-value, adjust if complex
    val mockedTeeEnforced: Map<String, String>    // Assuming simple key-value, adjust if complex
)

@Serializable
data class VerifyEcResponse(
    val sessionId: String,
    val isVerified: Boolean,
    val reason: String? = null,
    val decodedCertificateChain: DecodedCertificateChainMock,
    val attestationProperties: AttestationPropertiesMock
)
