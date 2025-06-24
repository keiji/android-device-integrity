package dev.keiji.deviceintegrity.ui.main.playintegrity

data class PlayIntegrityUiState(
    val nonce: String = "my-test-nonce", // Default nonce
    val isLoading: Boolean = false,
    val result: String = ""
)
