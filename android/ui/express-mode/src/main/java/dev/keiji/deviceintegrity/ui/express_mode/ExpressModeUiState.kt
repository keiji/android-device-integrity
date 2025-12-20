package dev.keiji.deviceintegrity.ui.express_mode

import dev.keiji.deviceintegrity.ui.common.InfoItem

data class ExpressModeUiState(
    val progress: Int = 0,
    val maxProgress: Int = 1,
    val resultInfoItems: List<InfoItem> = emptyList(),
    val status: String = "",
)
