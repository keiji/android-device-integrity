package dev.keiji.deviceintegrity.ui.main.playintegrity

data class ClassicPlayIntegrityUiState(
    val nonce: String = "",
    val integrityToken: String = "",
    val isLoading: Boolean = false,
    val status: String = ""
) {
    val isFetchNonceButtonEnabled: Boolean
        get() = !isLoading

    val isRequestTokenButtonEnabled: Boolean
        get() = !isLoading && nonce.isNotEmpty()

    val isVerifyTokenButtonEnabled: Boolean
        get() = !isLoading && integrityToken.isNotEmpty()
}
