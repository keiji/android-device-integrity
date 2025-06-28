package dev.keiji.deviceintegrity.ui.main.playintegrity

import dev.keiji.deviceintegrity.api.playintegrity.DeviceInfo
import dev.keiji.deviceintegrity.api.playintegrity.SecurityInfo
import dev.keiji.deviceintegrity.api.playintegrity.TokenPayloadExternal // Changed import

data class ClassicPlayIntegrityUiState(
    val nonce: String = "",
    val integrityToken: String = "",
    val isLoading: Boolean = false,
    val status: String = "",
    val playIntegrityResponse: TokenPayloadExternal? = null, // Renamed and type changed
    val deviceInfo: DeviceInfo? = null, // Added
    val securityInfo: SecurityInfo? = null, // Added
    val errorMessages: List<String> = emptyList(),
    val currentSessionId: String = ""
) {
    val isFetchNonceButtonEnabled: Boolean
        get() = !isLoading && errorMessages.isEmpty()

    val isRequestTokenButtonEnabled: Boolean
        get() = !isLoading && nonce.isNotEmpty()

    val isVerifyTokenButtonEnabled: Boolean
        get() = !isLoading && integrityToken.isNotEmpty()
}
