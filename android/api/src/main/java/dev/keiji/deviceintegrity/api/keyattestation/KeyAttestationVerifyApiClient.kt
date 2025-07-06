package dev.keiji.deviceintegrity.api.keyattestation

import dev.keiji.deviceintegrity.api.keyattestation.model.PrepareRequestBody
import dev.keiji.deviceintegrity.api.keyattestation.model.PrepareResponseBody
import dev.keiji.deviceintegrity.api.keyattestation.model.VerifyEcRequestBody
import dev.keiji.deviceintegrity.api.keyattestation.model.VerifyEcResponseBody
import retrofit2.http.Body
import retrofit2.http.POST

interface KeyAttestationVerifyApiClient {

    @POST("v1/prepare") // Ensure this path matches the server-side blueprint + endpoint path
    suspend fun prepare(
        @Body requestBody: PrepareRequestBody
    ): PrepareResponseBody

    @POST("v1/verify/ec") // Ensure this path matches the server-side blueprint + endpoint path
    suspend fun verifyEc(
        @Body requestBody: VerifyEcRequestBody
    ): VerifyEcResponseBody
}
