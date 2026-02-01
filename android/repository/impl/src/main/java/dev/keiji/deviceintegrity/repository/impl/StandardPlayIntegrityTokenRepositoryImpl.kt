package dev.keiji.deviceintegrity.repository.impl

import android.util.Base64
import com.google.android.play.core.integrity.StandardIntegrityManager
import dev.keiji.deviceintegrity.provider.contract.StandardIntegrityTokenProviderProvider
import dev.keiji.deviceintegrity.repository.contract.StandardPlayIntegrityTokenRepository
import kotlinx.coroutines.tasks.await
import timber.log.Timber
import java.security.MessageDigest
import javax.inject.Inject

/**
 * Implementation of [StandardPlayIntegrityTokenRepository] that uses the Google Play Integrity API.
 */
class StandardPlayIntegrityTokenRepositoryImpl @Inject constructor(
    private val standardIntegrityTokenProviderProvider: StandardIntegrityTokenProviderProvider
) : StandardPlayIntegrityTokenRepository {

    override suspend fun getToken(requestHash: String?): String {
        // Obtain StandardIntegrityManager via the provider.
        var integrityManager = standardIntegrityTokenProviderProvider.get()

        // Prepare the token request builder.
        val requestBuilder = StandardIntegrityManager.StandardIntegrityTokenRequest.builder()

        // The requestHash is now pre-calculated by the ViewModel (sessionId + contentBinding)
        // and Base64 URL-safe encoded.
        // The Play Integrity SDK expects a Base64 URL-safe encoded SHA-256 hash.
        // We need to ensure the hash passed here is already in that format.
        // The ViewModel's Base64 encoding uses NO_WRAP. The SDK example might use NO_PADDING as well.
        // Let's stick to NO_WRAP as used in ViewModel for now. If issues arise, check SDK requirements for Base64 flags.
        // The original code used: Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
        // ViewModel used: Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING. This is now consistent.
        // For now, assume requestHash is correctly formatted by the caller.
        if (!requestHash.isNullOrEmpty()) {
            requestBuilder.setRequestHash(requestHash)
        }

        val performRequest = suspend {
            // Request the integrity token.
            val tokenResponse = integrityManager.request(
                requestBuilder.build()
            ).await()

            tokenResponse.token() ?: throw IllegalStateException("Integrity token (standard) was null")
        }

        try {
            return performRequest()
        } catch (e: Exception) {
            Timber.w(e, "StandardIntegrityTokenProvider: Request failed. Retrying with a new provider.")
            standardIntegrityTokenProviderProvider.invalidate()
            integrityManager = standardIntegrityTokenProviderProvider.get()

            return performRequest()
        }
    }
}
