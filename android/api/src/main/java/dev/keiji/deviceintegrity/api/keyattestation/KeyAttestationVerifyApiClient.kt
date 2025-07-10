package dev.keiji.deviceintegrity.api.keyattestation

import retrofit2.http.Body
import retrofit2.http.POST

interface KeyAttestationVerifyApiClient {

    // Ensure this path matches the server-side endpoint path
    @POST("v1/prepare/signature")
    suspend fun prepareSignature(
        @Body requestBody: PrepareSignatureRequest
    ): PrepareResponse

    // Ensure this path matches the server-side endpoint path
    @POST("v1/verify/signature")
    suspend fun verifySignature(
        @Body requestBody: VerifySignatureRequest
    ): VerifySignatureResponse

    @POST("v1/prepare/agreement")
    suspend fun prepareAgreement(
        @Body requestBody: PrepareAgreementRequest
    ): PrepareAgreementResponse
}
