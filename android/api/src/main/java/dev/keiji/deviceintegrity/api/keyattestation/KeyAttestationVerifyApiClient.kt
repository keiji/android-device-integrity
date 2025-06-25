package dev.keiji.deviceintegrity.api.keyattestation

import retrofit2.http.Body
import retrofit2.http.POST

interface KeyAttestationVerifyApiClient {
    @POST("v1/verifyAttestation") // Dummy endpoint
    suspend fun verifyAttestation(@Body request: KeyAttestationRequest): KeyAttestationResponse
}

// Dummy request object
data class KeyAttestationRequest(
    val attestationStatement: String,
    val challenge: String
)

// Dummy response object
data class KeyAttestationResponse(
    val isValid: Boolean,
    val errorMessages: List<String>? = null
)
