package dev.keiji.deviceintegrity.repository.contract

/**
 * Interface for providing Google Play Integrity tokens using the standard request.
 */
interface StandardPlayIntegrityTokenRepository {
    /**
     * Retrieves a Google Play Integrity token using the standard request.
     *
     * @param contentToBind Optional. The original content string that will be hashed (SHA-256 then Base64URL)
     *                      and set as the request hash for the Play Integrity API call.
     *                      This same original content string should be sent to your server as 'contentBinding'.
     * @return The integrity token as a String.
     * @throws Exception if there is an issue retrieving the token.
     */
    suspend fun getToken(contentToBind: String?): String
}
