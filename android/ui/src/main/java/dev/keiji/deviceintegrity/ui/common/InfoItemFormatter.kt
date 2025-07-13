package dev.keiji.deviceintegrity.ui.common

import dev.keiji.deviceintegrity.ui.common.InfoItem

object InfoItemFormatter {
    fun formatInfoItems(items: List<InfoItem>): String {
        return items.joinToString("\n") { item ->
            val prefix = "".padStart(item.indentLevel * 2, ' ')
            if (item.isHeader) {
                "$prefix${item.label}"
            } else {
                "$prefix${item.label}: ${item.value}"
            }
        }
    }
}
