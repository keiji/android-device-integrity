package dev.keiji.deviceintegrity.ui.common

data class InfoItem(
    val label: String,
    val value: String,
    val isHeader: Boolean = false,
    val indentLevel: Int = 0
)
