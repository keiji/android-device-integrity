package dev.keiji.deviceintegrity.provider.contract

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class GooglePlayDeveloperServiceInfo(
    @SerialName("version_code")
    val versionCode: Long,
    @SerialName("version_name")
    val versionName: String,
)
