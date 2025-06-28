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
    val isFetchNonceButtonEnabled: Boolean
        get() = progressValue == 0.0F && errorMessages.isEmpty()

    val isRequestTokenButtonEnabled: Boolean
        get() = progressValue == 0.0F && nonce.isNotEmpty()

    val isVerifyTokenButtonEnabled: Boolean
        get() = progressValue == 0.0F && integrityToken.isNotEmpty()
}
