package dev.keiji.deviceintegrity.ui.main.keyattestation

object AttestationResultFormatter {
    fun formatAttestationResults(items: List<AttestationInfoItem>): String {
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
