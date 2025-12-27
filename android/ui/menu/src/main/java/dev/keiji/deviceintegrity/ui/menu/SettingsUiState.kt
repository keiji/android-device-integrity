package dev.keiji.deviceintegrity.ui.menu

data class SettingsUiState(
    val appVersionName: String,
    val appVersionCode: Long,
    val deviceName: String = "",
    val osVersion: String,
    val securityPatchLevel: String
)
