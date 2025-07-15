package dev.keiji.deviceintegrity.ui.main.playintegrity

import dev.keiji.deviceintegrity.api.playintegrity.ServerVerificationPayload
import dev.keiji.deviceintegrity.provider.contract.GooglePlayDeveloperServiceInfo
import dev.keiji.deviceintegrity.ui.common.InfoItem
import dev.keiji.deviceintegrity.ui.common.ProgressConstants

data class ClassicPlayIntegrityUiState(
    val nonce: String = "",
    val integrityToken: String = "",
    val progressValue: Float = ProgressConstants.NO_PROGRESS,
    val status: String = "",
    val serverVerificationPayload: ServerVerificationPayload? = null, // Keep for now, maybe used by other logic
    val googlePlayDeveloperServiceInfo: GooglePlayDeveloperServiceInfo? = null,
    val errorMessages: List<String> = emptyList(), // Will be combined into status for InfoItemContent
    val currentSessionId: String? = null,
    val resultInfoItems: List<InfoItem> = emptyList() // New field
) {
    val isLoading: Boolean
        get() = progressValue != ProgressConstants.NO_PROGRESS

    val isFetchNonceButtonEnabled: Boolean
        get() = !isLoading

    val isRequestTokenButtonEnabled: Boolean
        get() = !isLoading && nonce.isNotEmpty()

    val isVerifyTokenButtonEnabled: Boolean
        get() = !isLoading && nonce.isNotEmpty() && integrityToken.isNotEmpty()
}
