package dev.keiji.deviceintegrity.api.playintegrity

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import retrofit2.http.Body
import retrofit2.http.POST

interface PlayIntegrityTokenVerifyApiClient {
    @POST("/play-integrity/classic/nonce")
    suspend fun getNonce(@Body request: CreateNonceRequest): NonceResponse

    @POST("/play-integrity/classic/verify")
    suspend fun verifyToken(@Body request: VerifyTokenRequest): VerifyTokenResponse

    @POST("/play-integrity/standard/verify")
    suspend fun verifyTokenStandard(@Body request: StandardVerifyRequest): StandardVerifyResponse
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

@Serializable
data class DeviceInfo(
    @SerialName("brand") val brand: String?,
    @SerialName("model") val model: String?,
    @SerialName("device") val device: String?,
    @SerialName("product") val product: String?,
    @SerialName("manufacturer") val manufacturer: String?,
    @SerialName("hardware") val hardware: String?,
    @SerialName("board") val board: String?,
    @SerialName("bootloader") val bootloader: String?,
    @SerialName("version_release") val versionRelease: String?,
    @SerialName("sdk_int") val sdkInt: Int?,
    @SerialName("fingerprint") val fingerprint: String?,
    @SerialName("security_patch") val securityPatch: String?
)

@Serializable
data class SecurityInfo(
    @SerialName("is_device_lock_enabled") val isDeviceLockEnabled: Boolean?,
    @SerialName("is_biometrics_enabled") val isBiometricsEnabled: Boolean?,
    @SerialName("has_class3_authenticator") val hasClass3Authenticator: Boolean?,
    @SerialName("has_strongbox") val hasStrongbox: Boolean?
)

// Response for Standard API verification
// This models the direct response from the Play Integrity API as returned by our /standard/verify endpoint
@Serializable
data class StandardVerifyResponse(
    @SerialName("play_integrity_response") val playIntegrityResponse: TokenPayloadExternal,
    @SerialName("device_info") val deviceInfo: DeviceInfo? = null,
    @SerialName("security_info") val securityInfo: SecurityInfo? = null
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

// Response for Classic API verification.
// This now mirrors StandardVerifyResponse as both should return TokenPayloadExternal.
@Serializable
data class VerifyTokenResponse(
    @SerialName("play_integrity_response") val playIntegrityResponse: TokenPayloadExternal,
    @SerialName("device_info") val deviceInfo: DeviceInfo? = null,
    @SerialName("security_info") val securityInfo: SecurityInfo? = null
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
