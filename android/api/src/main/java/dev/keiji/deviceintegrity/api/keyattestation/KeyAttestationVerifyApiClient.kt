package dev.keiji.deviceintegrity.api.keyattestation

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST

interface KeyAttestationVerifyApiClient {

    // Ensure this path matches the server-side endpoint path
    @GET("key-attestation/v1/prepare/signature")
    suspend fun prepareSignature(): PrepareResponse

    // Ensure this path matches the server-side endpoint path
    @POST("key-attestation/v1/verify/signature")
    suspend fun verifySignature(
        @Body requestBody: VerifySignatureRequest
    ): VerifySignatureResponse

    @GET("key-attestation/v1/prepare/agreement")
    suspend fun prepareAgreement(): PrepareAgreementResponse

    @POST("key-attestation/v1/verify/agreement")
    suspend fun verifyAgreement(
        @Body requestBody: VerifyAgreementRequest
    ): VerifyAgreementResponse
}
