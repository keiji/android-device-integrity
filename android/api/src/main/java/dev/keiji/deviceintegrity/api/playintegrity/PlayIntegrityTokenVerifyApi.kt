package dev.keiji.deviceintegrity.api.playintegrity

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import retrofit2.http.Body
import retrofit2.http.POST

interface PlayIntegrityTokenVerifyApi {
    @POST("/play-integrity/classic/nonce")
    suspend fun getNonce(@Body request: NonceRequest): NonceResponse

    @POST("/play-integrity/classic/verify")
    suspend fun verifyToken(@Body request: VerifyTokenRequest): VerifyTokenResponse
}

@Serializable
data class NonceRequest(
    val someData: String // 必要に応じてリクエストのパラメータを定義してください
)

@Serializable
data class NonceResponse(
    val nonce: String,
    // TODO: Check actual response field name for TTL or generated_datetime
    val generated_datetime: Long
)

@Serializable
data class VerifyTokenRequest(
    val token: String,
    val nonce: String
)

// Data classes for Play Integrity API response structure
// Based on documentation: https://developer.android.com/google/play/integrity/verdict

// The VerifyTokenResponse directly models the JSON structure returned by the Play Integrity API,
// as our server forwards it directly.
// It also includes fields for potential errors reported by our own server.
@Serializable
data class VerifyTokenResponse(
    // Fields from the Play Integrity API JSON payload
    // Note: The Play Integrity API returns a top-level object that contains these.
    // The actual top-level object from Google is called TokenPayloadExternal in some contexts,
    // but the server /verify endpoint returns the *decoded* body of that token.
    // So, requestDetails, appIntegrity etc. are the top-level fields in the JSON we expect.
    val requestDetails: RequestDetails? = null,
    val appIntegrity: AppIntegrity? = null,
    val deviceIntegrity: DeviceIntegrity? = null,
    val accountDetails: AccountDetails? = null,
    val environmentDetails: EnvironmentDetails? = null,

    // Fields for errors originating from our server (e.g., nonce mismatch, server config error)
    val error: String? = null,
    val client_nonce: String? = null,
    val api_nonce: String? = null,
    // If our server encounters an error and decides to wrap/include the original Play Integrity response
    // (e.g. for a nonce mismatch where it still provides the PI response for debugging)
    // This field was part of the initial server implementation for nonce mismatch.
    // Changed to String for simplicity, assuming it's mainly for logging.
    // Renamed to camelCase for Kotlin convention, using @SerialName for JSON mapping.
    @SerialName("play_integrity_response")
    val playIntegrityResponse: String? = null
)

@Serializable
data class RequestDetails(
    val requestPackageName: String? = null,
    val nonce: String? = null, // For classic requests
    val requestHash: String? = null, // For standard requests
    val timestampMillis: String? = null // String in docs, but should be Long
)

@Serializable
data class AppIntegrity(
    val appRecognitionVerdict: String? = null,
    val packageName: String? = null,
    val certificateSha256Digest: List<String>? = null,
    val versionCode: String? = null // String in docs, but could be Long
)

@Serializable
data class DeviceIntegrity(
    val deviceRecognitionVerdict: List<String>? = null,
    val deviceAttributes: DeviceAttributes? = null,
    val recentDeviceActivity: RecentDeviceActivity? = null,
    // deviceRecall is beta and has a complex structure, omitting for now unless specifically requested
    // val deviceRecall: DeviceRecall? = null
)

@Serializable
data class DeviceAttributes(
    val sdkVersion: String? = null // String in docs, but represents an Int (API level)
)

@Serializable
data class RecentDeviceActivity(
    val deviceActivityLevel: String? = null
)

@Serializable
data class AccountDetails(
    val appLicensingVerdict: String? = null
)

@Serializable
data class EnvironmentDetails(
    val appAccessRiskVerdict: AppAccessRiskVerdict? = null,
    val playProtectVerdict: String? = null
)

@Serializable
data class AppAccessRiskVerdict(
    val appsDetected: List<String>? = null
)

// Note: For fields like timestampMillis, versionCode, sdkVersion,
// it's common for APIs to return them as strings even if they represent numbers.
// kotlinx.serialization can handle this, but direct conversion to Long/Int
// might be needed during consumption if strict typing is required.
// The server returns the whole Play Integrity API response, so these data classes
// model that structure directly.
