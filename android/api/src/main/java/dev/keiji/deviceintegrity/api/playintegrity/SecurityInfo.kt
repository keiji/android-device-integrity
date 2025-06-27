package dev.keiji.deviceintegrity.api.playintegrity

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class SecurityInfo(
    @SerialName("is_device_lock_enabled") val isDeviceLockEnabled: Boolean,
    @SerialName("is_biometrics_enabled") val isBiometricsEnabled: Boolean,
    @SerialName("has_class3_authenticator") val hasClass3Authenticator: Boolean,
    @SerialName("has_strongbox") val hasStrongbox: Boolean
)
