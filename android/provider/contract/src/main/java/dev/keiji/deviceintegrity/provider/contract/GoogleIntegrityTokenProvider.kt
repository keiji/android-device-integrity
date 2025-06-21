package dev.keiji.deviceintegrity.provider.contract

/**
 * Interface for providing Google Play Integrity tokens.
 */
interface GoogleIntegrityTokenProvider {
    /**
     * Retrieves a Google Play Integrity token.
     *
     * @param nonce A unique string that the server should generate and send to the client app.
     *              This nonce will be included in the signed integrity token.
     * @return The integrity token as a String.
     * @throws Exception if there is an issue retrieving the token. The specific exception
     *                   type will depend on the underlying cause (e.g., network issues,
     *                   Play Services not available, Integrity API errors).
     */
    suspend fun getToken(nonce: String): String
}
