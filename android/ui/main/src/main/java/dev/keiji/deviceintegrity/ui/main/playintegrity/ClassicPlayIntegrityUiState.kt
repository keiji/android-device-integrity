package dev.keiji.deviceintegrity.ui.main.playintegrity

import dev.keiji.deviceintegrity.api.playintegrity.VerifyTokenResponse

data class ClassicPlayIntegrityUiState(
    val nonce: String = "",
    val integrityToken: String = "",
    val isLoading: Boolean = false,
    val status: String = "",
    val verifyTokenResponse: VerifyTokenResponse? = null,
    val errorMessages: List<String> = emptyList()
) {
    val isFetchNonceButtonEnabled: Boolean
        get() = !isLoading && errorMessages.isEmpty()

    val isRequestTokenButtonEnabled: Boolean
        get() = !isLoading && nonce.isNotEmpty()

    val isVerifyTokenButtonEnabled: Boolean
        get() = !isLoading && integrityToken.isNotEmpty()
}
