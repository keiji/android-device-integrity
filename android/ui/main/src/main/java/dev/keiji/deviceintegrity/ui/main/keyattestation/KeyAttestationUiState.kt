package dev.keiji.deviceintegrity.ui.main.keyattestation

data class KeyAttestationUiState(
    val nonce: String = "",
    val isLoading: Boolean = false,
    val attestationResult: String? = null,
    val isNonceValid: Boolean = true // Assume valid initially or after generation
)
