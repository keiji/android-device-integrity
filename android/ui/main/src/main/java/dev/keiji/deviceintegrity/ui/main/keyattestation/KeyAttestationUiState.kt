package dev.keiji.deviceintegrity.ui.main.keyattestation

data class KeyAttestationUiState(
    val nonce: String = "",
    val challenge: String = "",
    val selectedKeyType: String = "EC", // Default to EC or the first option
    val status: String = ""
)
