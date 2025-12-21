package dev.keiji.deviceintegrity.ui.express_mode

import dev.keiji.deviceintegrity.ui.common.InfoItem

data class ExpressModeUiState(
    val progress: Int = 0,
    val maxProgress: Int = 1,
    val isProgressVisible: Boolean = true,
    val resultInfoItems: List<InfoItem> = emptyList(), // Deprecated but kept for compatibility if needed, though likely unused.
    val playIntegrityInfoItems: List<InfoItem> = emptyList(),
    val keyAttestationInfoItems: List<InfoItem> = emptyList(),
    val isPlayIntegritySuccess: Boolean = true,
    val isKeyAttestationSuccess: Boolean = true,
    val status: String = "",
)
