package dev.keiji.deviceintegrity.ui.main.util

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

object DateFormatUtil {
    fun formatEpochMilliToISO8601(epochMilli: Long?): String {
        if (epochMilli == null) return "N/A"
        val date = Date(epochMilli)
        // Use "XXX" for ISO 8601 time zone format (e.g., +09:00, -07:00, Z)
        // Locale.US is often used for consistency in formatting, but Locale.getDefault() could also be considered
        // if localized month/day names were part of the format, which they are not here.
        val format = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX", Locale.US)
        format.timeZone = TimeZone.getDefault() // Use device's local timezone
        return format.format(date)
    }
}
