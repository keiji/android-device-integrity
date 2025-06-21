package dev.keiji.deviceintegrity.ui.keyattestation

data class KeyAttestationUiState(
    val isLoading: Boolean = false,
    val result: String = "",
    val nonce: String = ""
)
