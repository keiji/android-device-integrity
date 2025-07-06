package dev.keiji.deviceintegrity.api.keyattestation

import kotlinx.serialization.Serializable
import kotlinx.serialization.SerialName

@Serializable
data class DecodedCertificateChainMock(
    @SerialName("mocked_detail")
    val mockedDetail: String
)

@Serializable
data class AttestationPropertiesMock(
    @SerialName("mocked_software_enforced")
    val mockedSoftwareEnforced: Map<String, String>,
    @SerialName("mocked_tee_enforced")
    val mockedTeeEnforced: Map<String, String>
)

@Serializable
data class VerifyEcResponse(
    @SerialName("session_id")
    val sessionId: String,
    @SerialName("is_verified")
    val isVerified: Boolean,
    @SerialName("reason")
    val reason: String? = null,
    @SerialName("decoded_certificate_chain")
    val decodedCertificateChain: DecodedCertificateChainMock,
    @SerialName("attestation_properties")
    val attestationProperties: AttestationPropertiesMock
)
