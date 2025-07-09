package dev.keiji.deviceintegrity.ui.main.util

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

object DateFormatUtil {
    fun formatEpochMilliToISO8601(epochMilli: Long?): String {
        if (epochMilli == null) return "N/A"
        val date = Date(epochMilli)
        // Replaced XXX with ZZZZZ for API level 23 compatibility.
        // ZZZZZ produces a format like "GMT-07:00" or "UTC" if UTC.
        // For UTC, it will be "UTC", to get "Z", one might need to replace "UTC" with "Z" manually.
        // However, the requirement is ISO/IEC 8601, and "yyyy-MM-dd'T'HH:mm:ss.SSSZZZZZ" is compliant.
        val format = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZZZZZ", Locale.US)
        format.timeZone = TimeZone.getTimeZone("UTC")
        var formattedDate = format.format(date)
        // Replace "UTC" with "Z" for the common ISO 8601 UTC designator
        if (formattedDate.endsWith("UTC")) {
            formattedDate = formattedDate.substring(0, formattedDate.length - 3) + "Z"
        }
        return formattedDate
    }
}
