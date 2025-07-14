package dev.keiji.deviceintegrity.ui.common

data class InfoItem(
    val label: String,
    val value: String? = null,
    val isHeader: Boolean = false,
    val indentLevel: Int = 0
) {
    companion object {
        val DIVIDER = InfoItem("DIVIDER", value = "", isHeader = true)
    }
}
