package dev.keiji.deviceintegrity.repository.contract

/**
 * Interface for providing Google Play Integrity tokens using the standard request.
 */
interface StandardPlayIntegrityTokenRepository {
    /**
     * Retrieves a Google Play Integrity token using the standard request.
     *
     * @param requestHash Optional. The pre-calculated SHA-256 hash of (sessionId + contentBinding), Base64 URL-safe encoded.
     *                    If null or empty, request hash will not be set in the Play Integrity API call.
     * @return The integrity token as a String.
     * @throws Exception if there is an issue retrieving the token.
     */
    suspend fun getToken(requestHash: String?): String
}
