package dev.keiji.deviceintegrity.repository.contract

/**
 * Interface for providing Google Play Integrity tokens using the classic request.
 */
interface ClassicPlayIntegrityTokenRepository {
    /**
     * Retrieves a Google Play Integrity token using the classic request.
     *
     * @param nonceBase64 A unique string that the server should generate and send to the client app.
     *                    This nonce will be included in the signed integrity token.
     *                    It must be Base64 encoded in web-safe no-wrap form.
     * @return The integrity token as a String.
     * @throws Exception if there is an issue retrieving the token. The specific exception
     *                   type will depend on the underlying cause (e.g., network issues,
     *                   Play Services not available, Integrity API errors).
     */
    suspend fun getToken(nonceBase64: String): String
}
