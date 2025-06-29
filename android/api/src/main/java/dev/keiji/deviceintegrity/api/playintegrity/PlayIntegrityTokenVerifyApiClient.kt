package dev.keiji.deviceintegrity.api.playintegrity

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import retrofit2.http.Body
import retrofit2.http.POST

private const val API_VERSION_V1 = "v1"

interface PlayIntegrityTokenVerifyApiClient {
    @POST("/play-integrity/classic/$API_VERSION_V1/nonce")
    suspend fun getNonce(@Body request: CreateNonceRequest): NonceResponse

    @POST("/play-integrity/classic/$API_VERSION_V1/verify")
    suspend fun verifyTokenClassic(@Body request: VerifyTokenRequest): ServerVerificationPayload

    @POST("/play-integrity/standard/$API_VERSION_V1/verify")
    suspend fun verifyTokenStandard(@Body request: StandardVerifyRequest): ServerVerificationPayload
}

// Request for creating a nonce
@Serializable
data class CreateNonceRequest(
    @SerialName("session_id") val sessionId: String
)

// Request for Standard API (similar to VerifyTokenRequest but for the new endpoint)
@Serializable
data class StandardVerifyRequest(
    @SerialName("token") val token: String,
    @SerialName("session_id") val sessionId: String,
    @SerialName("contentBinding") val contentBinding: String,
    @SerialName("device_info") val deviceInfo: DeviceInfo,
    @SerialName("security_info") val securityInfo: SecurityInfo
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

@Serializable
data class NonceResponse(
    val nonce: String,
    @SerialName("generated_datetime") val generatedDatetime: Long
)

@Serializable
data class VerifyTokenRequest(
    val token: String,
    @SerialName("session_id") val sessionId: String,
    @SerialName("device_info") val deviceInfo: DeviceInfo,
    @SerialName("security_info") val securityInfo: SecurityInfo
)

// Data classes for Play Integrity API response structure
// Based on documentation: https://developer.android.com/google/play/integrity/verdict

@Serializable
data class RequestDetails(
    val requestPackageName: String?,
    val nonce: String? = null, // Classic API
    val requestHash: String? = null, // Standard API
    @SerialName("timestampMillis") val timestampMillis: Long?
)

@Serializable
data class AppIntegrity(
    val appRecognitionVerdict: String?,
    val packageName: String?,
    val certificateSha256Digest: List<String>?,
    @SerialName("versionCode") val versionCode: Long?
)

@Serializable
data class DeviceIntegrity(
    val deviceRecognitionVerdict: List<String>?,
    val deviceAttributes: DeviceAttributes? = null,
    val recentDeviceActivity: RecentDeviceActivity? = null
)

@Serializable
data class DeviceAttributes(
    val sdkVersion: Int?
)

@Serializable
data class RecentDeviceActivity(
    val deviceActivityLevel: String?
)

@Serializable
data class AccountDetails(
    val appLicensingVerdict: String?
)

@Serializable
data class EnvironmentDetails(
    val appAccessRiskVerdict: AppAccessRiskVerdict? = null,
    val playProtectVerdict: String?
)

@Serializable
data class AppAccessRiskVerdict(
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
    @SerialName("client_provided_value") val clientProvidedValue: String,
    @SerialName("api_provided_value") val apiProvidedValue: String,
    @SerialName("play_integrity_response") val playIntegrityResponse: TokenPayloadExternal? = null
)
