package dev.keiji.deviceintegrity.ui.main.playintegrity

data class StandardPlayIntegrityUiState(
    val contentBinding: String = "", // For Standard Integrity API
    val isLoading: Boolean = false,
    val result: String = ""
)
