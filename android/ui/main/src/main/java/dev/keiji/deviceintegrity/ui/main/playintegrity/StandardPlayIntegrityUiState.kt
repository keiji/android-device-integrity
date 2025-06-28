package dev.keiji.deviceintegrity.ui.main.playintegrity

import dev.keiji.deviceintegrity.api.playintegrity.DeviceInfo
import dev.keiji.deviceintegrity.api.playintegrity.SecurityInfo
import dev.keiji.deviceintegrity.api.playintegrity.TokenPayloadExternal // Changed import

data class StandardPlayIntegrityUiState(
    val contentBinding: String = "", // For Standard Integrity API
    val integrityToken: String = "",
    val isLoading: Boolean = false,
    val status: String = "",
    val playIntegrityResponse: TokenPayloadExternal? = null, // Renamed and type changed
    val deviceInfo: DeviceInfo? = null, // Added
    val securityInfo: SecurityInfo? = null, // Added
    val errorMessages: List<String> = emptyList(),
    val requestHashValue: String = "",
    val currentSessionId: String = ""
) {
    val requestHashVisible: Boolean
        get() = requestHashValue.isNotEmpty()

    val isRequestTokenButtonEnabled: Boolean
        get() = !isLoading && contentBinding.isNotEmpty() && errorMessages.isEmpty()

    val isVerifyTokenButtonEnabled: Boolean
        get() = !isLoading && integrityToken.isNotEmpty()
}
