package dev.keiji.deviceintegrity.ui.main.playintegrity

import dev.keiji.deviceintegrity.api.playintegrity.DeviceInfo
import dev.keiji.deviceintegrity.api.playintegrity.SecurityInfo
import dev.keiji.deviceintegrity.api.playintegrity.TokenPayloadExternal
import dev.keiji.deviceintegrity.ui.main.playintegrity.PlayIntegrityProgressConstants // Import statement added

data class StandardPlayIntegrityUiState(
    val contentBinding: String = "",
    val integrityToken: String = "",
    val progressValue: Float = PlayIntegrityProgressConstants.NO_PROGRESS,
    val status: String = "",
    val playIntegrityResponse: TokenPayloadExternal? = null,
    val deviceInfo: DeviceInfo? = null,
    val securityInfo: SecurityInfo? = null,
    val errorMessages: List<String> = emptyList(),
    val requestHashValue: String = "",
    val currentSessionId: String = ""
) {
    val isLoading: Boolean
        get() = progressValue != PlayIntegrityProgressConstants.NO_PROGRESS

    val requestHashVisible: Boolean
        get() = requestHashValue.isNotEmpty()

    val isRequestTokenButtonEnabled: Boolean
        get() = !isLoading && contentBinding.isNotEmpty()

    val isVerifyTokenButtonEnabled: Boolean
        get() = !isLoading && integrityToken.isNotEmpty()
}
