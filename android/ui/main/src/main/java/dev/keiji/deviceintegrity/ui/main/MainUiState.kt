package dev.keiji.deviceintegrity.ui.main

data class MainUiState(
    val bottomNavigationItems: List<BottomNavigationItem> = emptyList(),
    val isKeyAttestationSupported: Boolean = false
)
