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
    @SerialName("purpose")
    val purpose: List<Int>? = null,
    @SerialName("algorithm")
    val algorithm: Int? = null,
    @SerialName("key_size")
    val keySize: Int? = null,
    @SerialName("digest")
    val digest: List<Int>? = null,
    @SerialName("padding")
    val padding: List<Int>? = null,
    @SerialName("ec_curve")
    val ecCurve: Int? = null,
    @SerialName("rsa_public_exponent")
    val rsaPublicExponent: Long? = null,
    @SerialName("mgf_digest")
    val mgfDigest: List<Int>? = null,
    @SerialName("rollback_resistance")
    val rollbackResistance: Boolean? = null,
    @SerialName("early_boot_only")
    val earlyBootOnly: Boolean? = null,
    @SerialName("active_date_time")
    val activeDateTime: Long? = null,
    @SerialName("origination_expire_date_time")
    val originationExpireDateTime: Long? = null,
    @SerialName("usage_expire_date_time")
    val usageExpireDateTime: Long? = null,
    @SerialName("usage_count_limit")
    val usageCountLimit: Int? = null,
    @SerialName("no_auth_required")
    val noAuthRequired: Boolean? = null,
    @SerialName("user_auth_type")
    val userAuthType: Int? = null,
    @SerialName("auth_timeout")
    val authTimeout: Int? = null,
    @SerialName("allow_while_on_body")
    val allowWhileOnBody: Boolean? = null,
    @SerialName("trusted_user_presence_required")
    val trustedUserPresenceRequired: Boolean? = null,
    @SerialName("trusted_confirmation_required")
    val trustedConfirmationRequired: Boolean? = null,
    @SerialName("unlocked_device_required")
    val unlockedDeviceRequired: Boolean? = null,
    @SerialName("creation_datetime")
    val creationDatetime: Long? = null,
    @SerialName("origin")
    val origin: Int? = null,
    @SerialName("root_of_trust")
    val rootOfTrust: RootOfTrust? = null,
    @SerialName("os_version")
    val osVersion: Int? = null,
    @SerialName("os_patch_level")
    val osPatchLevel: Int? = null,
    @SerialName("attestation_application_id")
    val attestationApplicationId: AttestationApplicationId? = null,
    @SerialName("attestation_id_brand")
    val attestationIdBrand: String? = null,
    @SerialName("attestation_id_device")
    val attestationIdDevice: String? = null,
    @SerialName("attestation_id_product")
    val attestationIdProduct: String? = null,
    @SerialName("attestation_id_serial")
    val attestationIdSerial: String? = null,
    @SerialName("attestation_id_imei")
    val attestationIdImei: String? = null,
    @SerialName("attestation_id_meid")
    val attestationIdMeid: String? = null,
    @SerialName("attestation_id_manufacturer")
    val attestationIdManufacturer: String? = null,
    @SerialName("attestation_id_model")
    val attestationIdModel: String? = null,
    @SerialName("vendor_patch_level")
    val vendorPatchLevel: Int? = null,
    @SerialName("boot_patch_level")
    val bootPatchLevel: Int? = null,
    @SerialName("device_unique_attestation")
    val deviceUniqueAttestation: Boolean? = null,
    @SerialName("attestation_id_second_imei")
    val attestationIdSecondImei: String? = null,
    @SerialName("module_hash")
    val moduleHash: String? = null
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
