package dev.keiji.deviceintegrity.ui.util

import kotlin.io.encoding.Base64
import kotlin.io.encoding.Base64.PaddingOption // Corrected import

/**
 * Utility object for Base64 encoding and decoding.
 */
object Base64Utils {

    /**
     * Provides a Base64 instance that is URL and filename safe (RFC 4648 section 5)
     * and configured to **not** use padding.
     *
     * Note: `kotlin.io.encoding.Base64.UrlSafe` by default uses `PaddingOption.PRESENT`.
     * This instance explicitly uses `PaddingOption.ABSENT`.
     */
    val UrlSafeNoPadding: Base64
        get() = Base64.UrlSafe.withPadding(PaddingOption.ABSENT)
}
