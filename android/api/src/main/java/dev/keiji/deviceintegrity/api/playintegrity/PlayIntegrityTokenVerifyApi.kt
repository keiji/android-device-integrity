package dev.keiji.deviceintegrity.api.playintegrity

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import retrofit2.http.Body
import retrofit2.http.POST

interface PlayIntegrityTokenVerifyApi {
    @POST("/play-integrity/classic/nonce")
    suspend fun getNonce(): NonceResponse // Removed @Body request: NonceRequest

    @POST("/play-integrity/classic/verify")
    suspend fun verifyToken(@Body request: VerifyTokenRequest): VerifyTokenResponse

    @POST("/play-integrity/standard/verify")
    suspend fun verifyTokenStandard(@Body request: StandardVerifyRequest): StandardVerifyResponse
}

// Request for Standard API (similar to VerifyTokenRequest but for the new endpoint)
@Serializable
data class StandardVerifyRequest(
    @SerialName("token") val token: String,
    @SerialName("nonce") val nonce: String
)

// Response for Standard API verification
// This models the direct response from the Play Integrity API as returned by our /standard/verify endpoint
@Serializable
data class StandardVerifyResponse(
    @SerialName("tokenPayloadExternal") val tokenPayloadExternal: TokenPayloadExternal
)

// Common wrapper for the actual integrity verdict, as per Google's documentation
// and our server's /verify and /standard/verify endpoint structure.
@Serializable
data class TokenPayloadExternal(
    // Based on OpenAPI, most of these are expected to be present in a successful response.
    // Nullability should be confirmed against what the server *actually* guarantees
    // for classic vs standard responses. For now, keeping them nullable as per original,
    // but a stricter definition based on server guarantees is better.
    @SerialName("requestDetails") val requestDetails: RequestDetails?,
    @SerialName("appIntegrity") val appIntegrity: AppIntegrity?,
    @SerialName("deviceIntegrity") val deviceIntegrity: DeviceIntegrity?,
    @SerialName("accountDetails") val accountDetails: AccountDetails?,
    @SerialName("environmentDetails") val environmentDetails: EnvironmentDetails? = null // EnvironmentDetails is often optional
)

// NonceRequest data class is removed as it's not needed.

@Serializable
data class NonceResponse(
    val nonce: String,
    @SerialName("generated_datetime") val generatedDatetime: Long // Field name matches OpenAPI, type is Long
)

@Serializable
data class VerifyTokenRequest(
    val token: String,
    val nonce: String
)

// Response for Classic API verification.
// This now mirrors StandardVerifyResponse as both should return TokenPayloadExternal.
@Serializable
data class VerifyTokenResponse(
    @SerialName("tokenPayloadExternal") val tokenPayloadExternal: TokenPayloadExternal
)

// Data classes for Play Integrity API response structure
// Based on documentation: https://developer.android.com/google/play/integrity/verdict

@Serializable
data class RequestDetails(
    val requestPackageName: String?,
    val nonce: String?, // For classic requests
    val requestHash: String? = null, // For standard requests - often null in classic
    @SerialName("timestampMillis") val timestampMillis: Long? // Changed to Long?
)

@Serializable
data class AppIntegrity(
    val appRecognitionVerdict: String?,
    val packageName: String?,
    val certificateSha256Digest: List<String>?,
    @SerialName("versionCode") val versionCode: Long? // Changed to Long? (or Int? if appropriate)
)

@Serializable
data class DeviceIntegrity(
    val deviceRecognitionVerdict: List<String>?,
    val deviceAttributes: DeviceAttributes? = null, // Standard API only
    val recentDeviceActivity: RecentDeviceActivity? = null // Standard API only
)

@Serializable
data class DeviceAttributes( // Standard API only
    val sdkVersion: String? // String in docs, but represents an Int (API level)
    // It might be better to keep as String if server sends it as String, or use a custom serializer.
    // For now, keeping as String? to match original cautious typing.
)

@Serializable
data class RecentDeviceActivity( // Standard API only
    val deviceActivityLevel: String?
)

@Serializable
data class AccountDetails(
    val appLicensingVerdict: String?
)

@Serializable
data class EnvironmentDetails( // Optional in classic, more common in standard
    val appAccessRiskVerdict: AppAccessRiskVerdict? = null, // Standard API only
    val playProtectVerdict: String?
)

@Serializable
data class AppAccessRiskVerdict( // Standard API only
    val appsDetected: List<String>? = null
)


// --- Error Response Data Classes ---
@Serializable
data class ApiErrorResponse(
    val error: String
)

@Serializable
data class NonceMismatchErrorResponse(
    val error: String,
    @SerialName("client_nonce") val clientNonce: String,
    @SerialName("api_nonce") val apiNonce: String,
    // As per OpenAPI, this should be an object, mapping to TokenPayloadExternal
    @SerialName("play_integrity_response") val playIntegrityResponse: TokenPayloadExternal? = null
)

// Note:
// 1. Nullability of fields in TokenPayloadExternal and its nested classes:
//    The current OpenAPI definition for /classic/verify response doesn't explicitly mark all sub-fields
//    within tokenPayloadExternal as required. It's safer to keep them nullable for now or
//    verify against actual server responses for classic requests. Standard requests might provide more fields.
//    The example in OpenAPI suggests many fields are present.
// 2. `versionCode` changed to `Long?`. If it can exceed Int.MAX_VALUE, Long is safer. Otherwise Int is fine.
// 3. `timestampMillis` changed to `Long?`.
// 4. `DeviceAttributes`, `RecentDeviceActivity`, `AppAccessRiskVerdict` are typically part of Standard API responses.
//    They are kept nullable here. If classic API *never* returns them, they could be removed from
//    general TokenPayloadExternal if we had separate models for classic and standard, but sharing is common.
//    The current OpenAPI also includes them in the example for classic, so keeping them.
