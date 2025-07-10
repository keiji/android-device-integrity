package dev.keiji.deviceintegrity.ui.main

data class InfoItem(
    val label: String,
    val value: String,
    val isHeader: Boolean = false,
    val indentLevel: Int = 0
)
