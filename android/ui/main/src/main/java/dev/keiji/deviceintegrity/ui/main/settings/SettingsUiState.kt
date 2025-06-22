package dev.keiji.deviceintegrity.ui.main.settings

data class SettingsUiState(
    val appVersionName: String,
    val appVersionCode: Long,
    val osVersion: String,
    val securityPatchLevel: String
)
