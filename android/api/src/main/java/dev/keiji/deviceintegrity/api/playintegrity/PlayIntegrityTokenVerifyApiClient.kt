package dev.keiji.deviceintegrity.api.playintegrity

import dev.keiji.deviceintegrity.provider.contract.GooglePlayDeveloperServiceInfo
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
    @SerialName("security_info") val securityInfo: SecurityInfo,
    @SerialName("google_play_developer_service_info") val googlePlayDeveloperServiceInfo: GooglePlayDeveloperServiceInfo? = null,
)

// Common wrapper for the actual integrity verdict, as per Google's documentation
// and our server's /verify and /standard/verify endpoint structure.
@Serializable
data class TokenPayloadExternal(
    // Based on OpenAPI, most of these are expected to be present in a successful response.
    // Nullability should be confirmed against what the server *actually* guarantees
    // for classic vs standard responses. For now, keeping them nullable as per original,
    // but a stricter definition based on server guarantees is better.
    @SerialName("request_details") val requestDetails: RequestDetails?,
    @SerialName("app_integrity") val appIntegrity: AppIntegrity?,
    @SerialName("device_integrity") val deviceIntegrity: DeviceIntegrity?,
    @SerialName("account_details") val accountDetails: AccountDetails?,
    @SerialName("environment_details") val environmentDetails: EnvironmentDetails? = null // EnvironmentDetails is often optional
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
    @SerialName("security_info") val securityInfo: SecurityInfo,
    @SerialName("google_play_developer_service_info") val googlePlayDeveloperServiceInfo: GooglePlayDeveloperServiceInfo? = null,
)

// Data classes for Play Integrity API response structure
// Based on documentation: https://developer.android.com/google/play/integrity/verdict

@Serializable
data class RequestDetails(
    @SerialName("request_package_name") val requestPackageName: String?,
    @SerialName("nonce") val nonce: String? = null, // Classic API, already snake_case
    @SerialName("request_hash") val requestHash: String? = null, // Standard API
    @SerialName("timestamp_millis") val timestampMillis: Long?
)

@Serializable
data class AppIntegrity(
    @SerialName("app_recognition_verdict") val appRecognitionVerdict: String?,
    @SerialName("package_name") val packageName: String?,
    @SerialName("certificate_sha256_digest") val certificateSha256Digest: List<String>?,
    @SerialName("version_code") val versionCode: Long?
)

@Serializable
data class DeviceIntegrity(
    @SerialName("device_recognition_verdict") val deviceRecognitionVerdict: List<String>?,
    @SerialName("device_attributes") val deviceAttributes: DeviceAttributes? = null,
    @SerialName("recent_device_activity") val recentDeviceActivity: RecentDeviceActivity? = null
)

@Serializable
data class DeviceAttributes(
    @SerialName("sdk_version") val sdkVersion: Int? // Assuming it was meant to be sdk_version from OpenAPI
)

@Serializable
data class RecentDeviceActivity(
    @SerialName("device_activity_level") val deviceActivityLevel: String? // Assuming device_activity_level
)

@Serializable
data class AccountDetails(
    @SerialName("app_licensing_verdict") val appLicensingVerdict: String?
)

@Serializable
data class EnvironmentDetails(
    @SerialName("app_access_risk_verdict") val appAccessRiskVerdict: AppAccessRiskVerdict? = null,
    @SerialName("play_protect_verdict") val playProtectVerdict: String? // Assuming play_protect_verdict
)

@Serializable
data class AppAccessRiskVerdict(
    @SerialName("apps_detected") val appsDetected: List<String>? = null // Assuming apps_detected
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
