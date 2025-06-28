package dev.keiji.deviceintegrity.ui.main.playintegrity

import dev.keiji.deviceintegrity.api.playintegrity.DeviceInfo
import dev.keiji.deviceintegrity.api.playintegrity.SecurityInfo
import dev.keiji.deviceintegrity.api.playintegrity.TokenPayloadExternal

data class StandardPlayIntegrityUiState(
    val contentBinding: String = "",
    val integrityToken: String = "",
    val progressValue: Float = 0.0F,
    val status: String = "",
    val playIntegrityResponse: TokenPayloadExternal? = null,
    val deviceInfo: DeviceInfo? = null,
    val securityInfo: SecurityInfo? = null,
    val errorMessages: List<String> = emptyList(),
    val requestHashValue: String = "",
    val currentSessionId: String = ""
) {
    val isLoading: Boolean
        get() = progressValue != 0.0F

    val requestHashVisible: Boolean
        get() = requestHashValue.isNotEmpty()

    val isRequestTokenButtonEnabled: Boolean
        get() = !isLoading && contentBinding.isNotEmpty() && errorMessages.isEmpty()

    val isVerifyTokenButtonEnabled: Boolean
        get() = !isLoading && integrityToken.isNotEmpty()
}
