package dev.keiji.deviceintegrity.api.keyattestation

import dev.keiji.deviceintegrity.api.DeviceInfo
import dev.keiji.deviceintegrity.api.SecurityInfo
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class AttestationApplicationId(
    @SerialName("application_signatures")
    val applicationSignatures: List<String>,
    @SerialName("attestation_application_id")
    val attestationApplicationId: String,
    @SerialName("attestation_application_version_code")
    val attestationApplicationVersionCode: Int
)

@Serializable
data class RootOfTrust(
    @SerialName("device_locked")
    val deviceLocked: Boolean,
    @SerialName("verified_boot_hash")
    val verifiedBootHash: String,
    @SerialName("verified_boot_key")
    val verifiedBootKey: String,
    @SerialName("verified_boot_state")
    val verifiedBootState: Int
)

@Serializable
data class AuthorizationList(
    @SerialName("attestation_application_id")
    val attestationApplicationId: AttestationApplicationId? = null,
    @SerialName("creation_datetime")
    val creationDatetime: Long? = null,
    @SerialName("algorithm")
    val algorithm: Int? = null,
    @SerialName("boot_patch_level")
    val bootPatchLevel: Int? = null,
    @SerialName("digests")
    val digests: List<Int>? = null,
    @SerialName("ec_curve")
    val ecCurve: Int? = null,
    @SerialName("key_size")
    val keySize: Int? = null,
    @SerialName("no_auth_required")
    val noAuthRequired: Boolean? = null,
    @SerialName("origin")
    val origin: Int? = null,
    @SerialName("os_patch_level")
    val osPatchLevel: Int? = null,
    @SerialName("os_version")
    val osVersion: Int? = null,
    @SerialName("purpose")
    val purpose: List<Int>? = null,
    @SerialName("root_of_trust")
    val rootOfTrust: RootOfTrust? = null,
    @SerialName("vendor_patch_level")
    val vendorPatchLevel: Int? = null
)

@Serializable
data class AttestationInfo(
    @SerialName("attestation_security_level")
    val attestationSecurityLevel: Int,
    @SerialName("attestation_version")
    val attestationVersion: Int,
    @SerialName("keymint_security_level")
    val keymintSecurityLevel: Int,
    @SerialName("keymint_version")
    val keymintVersion: Int,
    @SerialName("attestation_challenge")
    val attestationChallenge: String,
    @SerialName("software_enforced_properties")
    val softwareEnforcedProperties: AuthorizationList,
    @SerialName("hardware_enforced_properties")
    val hardwareEnforcedProperties: AuthorizationList
)

@Serializable
data class VerifySignatureResponse(
    @SerialName("is_verified")
    val isVerified: Boolean,
    @SerialName("reason")
    val reason: String? = null,
    @SerialName("session_id")
    val sessionId: String,
    @SerialName("attestation_info")
    val attestationInfo: AttestationInfo,
    @SerialName("device_info")
    val deviceInfo: DeviceInfo,
    @SerialName("security_info")
    val securityInfo: SecurityInfo
)
