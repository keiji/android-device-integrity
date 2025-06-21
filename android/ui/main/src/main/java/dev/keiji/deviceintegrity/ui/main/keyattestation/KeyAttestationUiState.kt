package dev.keiji.deviceintegrity.ui.main.keyattestation

data class KeyAttestationUiState(
    val isLoading: Boolean = false,
    val result: String = "",
    val nonce: String = ""
)
