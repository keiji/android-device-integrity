package dev.keiji.deviceintegrity.ui.main.playintegrity

import dev.keiji.deviceintegrity.api.playintegrity.StandardVerifyResponse

data class StandardPlayIntegrityUiState(
    val contentBinding: String = "", // For Standard Integrity API
    val integrityToken: String = "",
    val isLoading: Boolean = false,
    val status: String = "",
    val standardVerifyResponse: StandardVerifyResponse? = null,
    val errorMessages: List<String> = emptyList()
) {
    val isRequestTokenButtonEnabled: Boolean
        get() = !isLoading && contentBinding.isNotEmpty() && errorMessages.isEmpty()

    val isVerifyTokenButtonEnabled: Boolean
        get() = !isLoading && integrityToken.isNotEmpty()
}
