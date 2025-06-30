package dev.keiji.deviceintegrity.ui.main.playintegrity

import dev.keiji.deviceintegrity.api.playintegrity.ServerVerificationPayload
import dev.keiji.deviceintegrity.provider.contract.GooglePlayDeveloperServiceInfo

data class StandardPlayIntegrityUiState(
    val contentBinding: String = "",
    val integrityToken: String = "",
    val progressValue: Float = PlayIntegrityProgressConstants.NO_PROGRESS,
    val status: String = "",
    val serverVerificationPayload: ServerVerificationPayload? = null,
    val errorMessages: List<String> = emptyList(),
    val requestHashValue: String = "",
    val currentSessionId: String = "",
    val googlePlayDeveloperServiceInfo: GooglePlayDeveloperServiceInfo? = null
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
