package dev.keiji.deviceintegrity.ui.main.playintegrity

data class ClassicPlayIntegrityUiState(
    val nonce: String = "my-test-nonce", // Default nonce
    val isLoading: Boolean = false,
    val result: String = ""
)
