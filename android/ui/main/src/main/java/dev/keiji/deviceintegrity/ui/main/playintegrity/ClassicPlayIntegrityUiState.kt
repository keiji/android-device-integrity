package dev.keiji.deviceintegrity.ui.main.playintegrity

import dev.keiji.deviceintegrity.api.playintegrity.DeviceInfo
import dev.keiji.deviceintegrity.api.playintegrity.SecurityInfo
import dev.keiji.deviceintegrity.api.playintegrity.TokenPayloadExternal
import dev.keiji.deviceintegrity.provider.contract.GooglePlayDeveloperServiceInfo
import dev.keiji.deviceintegrity.ui.main.playintegrity.PlayIntegrityProgressConstants // Import statement added

data class ClassicPlayIntegrityUiState(
    val nonce: String = "",
    val integrityToken: String = "",
    val progressValue: Float = PlayIntegrityProgressConstants.NO_PROGRESS,
    val status: String = "",
    val playIntegrityResponse: TokenPayloadExternal? = null,
    val deviceInfo: DeviceInfo? = null,
    val securityInfo: SecurityInfo? = null,
    val googlePlayDeveloperServiceInfo: GooglePlayDeveloperServiceInfo? = null,
    val errorMessages: List<String> = emptyList(),
    val currentSessionId: String = ""
) {
    val isLoading: Boolean
        get() = progressValue != PlayIntegrityProgressConstants.NO_PROGRESS

    val isFetchNonceButtonEnabled: Boolean
        get() = !isLoading

    val isRequestTokenButtonEnabled: Boolean
        get() = !isLoading && nonce.isNotEmpty()

    val isVerifyTokenButtonEnabled: Boolean
        get() = !isLoading && nonce.isNotEmpty() && integrityToken.isNotEmpty()
}
