package dev.keiji.deviceintegrity.repository.contract

/**
 * Interface for providing Google Play Integrity tokens.
 */
interface GooglePlayIntegrityTokenRepository {
    /**
     * Retrieves a Google Play Integrity token using the classic request.
     *
     * @param nonce A unique string that the server should generate and send to the client app.
     *              This nonce will be included in the signed integrity token.
     * @return The integrity token as a String.
     * @throws Exception if there is an issue retrieving the token. The specific exception
     *                   type will depend on the underlying cause (e.g., network issues,
     *                   Play Services not available, Integrity API errors).
     */
    suspend fun getTokenClassic(nonce: String): String

    /**
     * Retrieves a Google Play Integrity token using the standard request.
     *
     * @param cloudProjectNumber The Google Cloud project number.
     * @param requestHash Optional. A hash of the request that the server is making to your app.
     * @return The integrity token as a String.
     * @throws Exception if there is an issue retrieving the token.
     */
    suspend fun getTokenStandard(cloudProjectNumber: Long, requestHash: String?): String
}
