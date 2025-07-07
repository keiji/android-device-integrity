package dev.keiji.deviceintegrity.api.keyattestation

import kotlinx.serialization.Serializable
import kotlinx.serialization.SerialName

@Serializable
data class AttestationApplicationId(
    @SerialName("application_signature")
    val applicationSignature: String?, // Made nullable
    @SerialName("attestation_application_id")
    val attestationApplicationId: String?, // Made nullable
    @SerialName("attestation_application_version_code")
    val attestationApplicationVersionCode: Int? // Made nullable
)

@Serializable
data class RootOfTrust(
    @SerialName("device_locked")
    val deviceLocked: Boolean?, // Made nullable
    @SerialName("verified_boot_hash")
    val verifiedBootHash: String?, // Made nullable
    @SerialName("verified_boot_key")
    val verifiedBootKey: String?, // Made nullable
    @SerialName("verified_boot_state")
    val verifiedBootState: Int? // Made nullable
)

@Serializable
data class AuthorizationList(
    // Fields from SoftwareEnforced
    @SerialName("attestation_application_id")
    val attestationApplicationId: AttestationApplicationId?,
    @SerialName("creation_datetime")
    val creationDatetime: Long?,

    // Fields from TeeEnforced
    @SerialName("algorithm")
    val algorithm: Int?,
    @SerialName("boot_patch_level")
    val bootPatchLevel: Int?,
    @SerialName("digests")
    val digests: List<Int>?,
    @SerialName("ec_curve")
    val ecCurve: Int?,
    @SerialName("key_size")
    val keySize: Int?,
    @SerialName("no_auth_required")
    val noAuthRequired: Boolean?,
    @SerialName("origin")
    val origin: String?,
    @SerialName("os_patch_level")
    val osPatchLevel: Int?,
    @SerialName("os_version")
    val osVersion: Int?,
    @SerialName("purpose")
    val purpose: List<Int>?,
    @SerialName("root_of_trust")
    val rootOfTrust: RootOfTrust?,
    @SerialName("vendor_patch_level")
    val vendorPatchLevel: Int?
)

@Serializable
data class VerifyEcResponse(
    @SerialName("attestation_security_level")
    val attestationSecurityLevel: Int,
    @SerialName("attestation_version")
    val attestationVersion: Int,
    @SerialName("is_verified")
    val isVerified: Boolean,
    @SerialName("keymint_security_level")
    val keymintSecurityLevel: Int,
    @SerialName("keymint_version")
    val keymintVersion: Int,
    @SerialName("reason")
    val reason: String? = null,
    @SerialName("session_id")
    val sessionId: String,
    @SerialName("software_enforced_properties")
    val softwareEnforcedProperties: AuthorizationList?, // Changed to AuthorizationList?
    @SerialName("tee_enforced_properties")
    val teeEnforcedProperties: AuthorizationList? // Changed to AuthorizationList?
)
