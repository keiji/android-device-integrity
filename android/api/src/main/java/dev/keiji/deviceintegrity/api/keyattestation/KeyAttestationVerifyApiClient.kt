package dev.keiji.deviceintegrity.api.keyattestation

import dev.keiji.deviceintegrity.api.keyattestation.PrepareRequest
import dev.keiji.deviceintegrity.api.keyattestation.PrepareResponse
import dev.keiji.deviceintegrity.api.keyattestation.VerifyEcRequest
import dev.keiji.deviceintegrity.api.keyattestation.VerifyEcResponse
import retrofit2.http.Body
import retrofit2.http.POST

interface KeyAttestationVerifyApiClient {

    // Ensure this path matches the server-side endpoint path
    @POST("v1/prepare")
    suspend fun prepare(
        @Body requestBody: PrepareRequest
    ): PrepareResponse

    // Ensure this path matches the server-side endpoint path
    @POST("v1/verify/ec")
    suspend fun verifyEc(
        @Body requestBody: VerifyEcRequest
    ): VerifyEcResponse
}
