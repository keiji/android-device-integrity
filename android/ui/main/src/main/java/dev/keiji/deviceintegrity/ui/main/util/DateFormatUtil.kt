package dev.keiji.deviceintegrity.ui.main.util

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

object DateFormatUtil {
    fun formatEpochMilliToISO8601(epochMilli: Long?): String {
        if (epochMilli == null) return "N/A"
        val date = Date(epochMilli)
        // Use "ZZZZZ" for compatibility (as noted in original KeyAttestationViewModel comments for API 23)
        // This produces a format like "GMT-07:00" or "GMT+09:00".
        // Locale.US is kept from the original KeyAttestationViewModel's implementation.
        val format = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZZZZZ", Locale.US)
        format.timeZone = TimeZone.getDefault() // Use device's local timezone
        return format.format(date)
    }
}
