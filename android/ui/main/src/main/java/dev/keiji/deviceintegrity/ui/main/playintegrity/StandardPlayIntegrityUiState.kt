package dev.keiji.deviceintegrity.ui.main.playintegrity

data class StandardPlayIntegrityUiState(
    val contentBinding: String = "", // For Standard Integrity API
    val integrityToken: String = "",
    val isLoading: Boolean = false,
    val status: String = ""
) {
    val isRequestTokenButtonEnabled: Boolean
        get() = !isLoading && contentBinding.isNotEmpty()

    val isVerifyTokenButtonEnabled: Boolean
        get() = !isLoading && integrityToken.isNotEmpty()
}
