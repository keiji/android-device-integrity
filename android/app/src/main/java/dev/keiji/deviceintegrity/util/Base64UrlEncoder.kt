package dev.keiji.deviceintegrity.util

import java.util.Base64

object Base64UrlEncoder {

    fun encodeNoPadding(data: ByteArray): String {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data)
    }

    fun decode(encodedString: String): ByteArray {
        return Base64.getUrlDecoder().decode(encodedString)
    }
}
