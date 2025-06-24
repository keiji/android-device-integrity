package dev.keiji.deviceintegrity.api_endpoint_settings.validation

object ValidationConstants {
    val ALLOWED_URL_CHARACTERS: Set<Char> = setOf(
        ':', '/', '?', '#', '[', ']', '@', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', '-', '_', '.', '~', '%'
    )
    const val INVALID_URL_FORMAT_ERROR_MESSAGE = "Invalid URL format"
}
