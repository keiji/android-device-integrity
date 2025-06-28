package dev.keiji.deviceintegrity.ui.main.playintegrity

import dev.keiji.deviceintegrity.api.playintegrity.DeviceInfo
import dev.keiji.deviceintegrity.api.playintegrity.SecurityInfo
import dev.keiji.deviceintegrity.api.playintegrity.TokenPayloadExternal

data class ClassicPlayIntegrityUiState(
    val nonce: String = "",
    val integrityToken: String = "",
    val progressValue: Float = 0.0F,
    val status: String = "",
    val playIntegrityResponse: TokenPayloadExternal? = null,
    val deviceInfo: DeviceInfo? = null,
    val securityInfo: SecurityInfo? = null,
    val errorMessages: List<String> = emptyList(),
    val currentSessionId: String = ""
) {
    val isLoading: Boolean
        get() = progressValue != 0.0F

    val isFetchNonceButtonEnabled: Boolean
        get() = !isLoading && errorMessages.isEmpty()

    val isRequestTokenButtonEnabled: Boolean
        get() = !isLoading && nonce.isNotEmpty()

    val isVerifyTokenButtonEnabled: Boolean
        get() = !isLoading && integrityToken.isNotEmpty()
}
