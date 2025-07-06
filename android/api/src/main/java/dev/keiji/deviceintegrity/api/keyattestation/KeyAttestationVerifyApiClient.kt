package dev.keiji.deviceintegrity.api.keyattestation

import com.google.gson.annotations.SerializedName
import retrofit2.http.Body
import retrofit2.http.POST

interface KeyAttestationVerifyApiClient {
    @POST("v1/verifyAttestation") // Dummy endpoint
    suspend fun verifyAttestation(@Body request: KeyAttestationRequest): KeyAttestationResponse
}

// Dummy request object
data class KeyAttestationRequest(
    @SerializedName("attestation_statement")
    val attestationStatement: String,
    val challenge: String
)

// Dummy response object
data class KeyAttestationResponse(
    @SerializedName("is_valid")
    val isValid: Boolean,
    @SerializedName("error_messages")
    val errorMessages: List<String>? = null
)
