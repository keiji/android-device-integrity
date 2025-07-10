package dev.keiji.deviceintegrity.ui.main.playintegrity

import dev.keiji.deviceintegrity.api.playintegrity.ServerVerificationPayload
import dev.keiji.deviceintegrity.provider.contract.GooglePlayDeveloperServiceInfo
import dev.keiji.deviceintegrity.ui.main.InfoItem

data class StandardPlayIntegrityUiState(
    val contentBinding: String = "",
    val integrityToken: String = "",
    val progressValue: Float = PlayIntegrityProgressConstants.NO_PROGRESS,
    val status: String = "",
    val serverVerificationPayload: ServerVerificationPayload? = null, // Keep for now
    val errorMessages: List<String> = emptyList(), // Will be combined into status
    val requestHashValue: String = "",
    val currentSessionId: String = "",
    val googlePlayDeveloperServiceInfo: GooglePlayDeveloperServiceInfo? = null,
    val resultInfoItems: List<InfoItem> = emptyList() // New field
) {
    val isLoading: Boolean
        get() = progressValue != PlayIntegrityProgressConstants.NO_PROGRESS

    val requestHashVisible: Boolean
        get() = requestHashValue.isNotEmpty()

    val isRequestTokenButtonEnabled: Boolean
        get() = !isLoading // Allow empty contentBinding

    val isVerifyTokenButtonEnabled: Boolean
        get() = !isLoading && integrityToken.isNotEmpty()
}
