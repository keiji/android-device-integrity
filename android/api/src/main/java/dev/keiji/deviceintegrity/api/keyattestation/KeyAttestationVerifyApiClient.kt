package dev.keiji.deviceintegrity.api.keyattestation

import dev.keiji.deviceintegrity.api.keyattestation.model.PrepareRequest
import dev.keiji.deviceintegrity.api.keyattestation.model.PrepareResponse
import dev.keiji.deviceintegrity.api.keyattestation.model.VerifyEcRequest
import dev.keiji.deviceintegrity.api.keyattestation.model.VerifyEcResponse
import retrofit2.http.Body
import retrofit2.http.POST

interface KeyAttestationVerifyApiClient {

    @POST("v1/prepare") // Ensure this path matches the server-side blueprint + endpoint path
    suspend fun prepare(
        @Body requestBody: PrepareRequest
    ): PrepareResponse

    @POST("v1/verify/ec") // Ensure this path matches the server-side blueprint + endpoint path
    suspend fun verifyEc(
        @Body requestBody: VerifyEcRequest
    ): VerifyEcResponse
}
