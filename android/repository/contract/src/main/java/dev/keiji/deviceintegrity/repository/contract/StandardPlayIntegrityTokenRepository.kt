package dev.keiji.deviceintegrity.repository.contract

/**
 * Interface for providing Google Play Integrity tokens using the standard request.
 */
interface StandardPlayIntegrityTokenRepository {
    /**
     * Retrieves a Google Play Integrity token using the standard request.
     *
     * @param requestHash Optional. A hash of the request that the server is making to your app.
     * @return The integrity token as a String.
     * @throws Exception if there is an issue retrieving the token.
     */
    suspend fun getToken(requestHash: String?): String
}
