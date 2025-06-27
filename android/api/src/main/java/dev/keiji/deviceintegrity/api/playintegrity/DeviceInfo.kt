package dev.keiji.deviceintegrity.api.playintegrity

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class DeviceInfo(
    @SerialName("brand") val brand: String,
    @SerialName("model") val model: String,
    @SerialName("device") val device: String,
    @SerialName("product") val product: String,
    @SerialName("manufacturer") val manufacturer: String,
    @SerialName("hardware") val hardware: String,
    @SerialName("board") val board: String,
    @SerialName("bootloader") val bootloader: String,
    @SerialName("version_release") val versionRelease: String,
    @SerialName("sdk_int") val sdkInt: Int,
    @SerialName("fingerprint") val fingerprint: String,
    @SerialName("security_patch") val securityPatch: String
)
