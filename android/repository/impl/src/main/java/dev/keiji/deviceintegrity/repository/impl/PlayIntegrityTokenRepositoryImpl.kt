package dev.keiji.deviceintegrity.repository.impl

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import com.google.android.play.core.integrity.StandardIntegrityManager
import dev.keiji.deviceintegrity.provider.contract.StandardIntegrityTokenProviderProvider
import dev.keiji.deviceintegrity.repository.contract.PlayIntegrityTokenRepository
import kotlinx.coroutines.tasks.await
import javax.inject.Inject

/**
 * Implementation of [PlayIntegrityTokenRepository] that uses the Google Play Integrity API.
 */
class PlayIntegrityTokenRepositoryImpl @Inject constructor(
    private val context: Context, // Kept for classic requests
    private val standardIntegrityTokenProviderProvider: StandardIntegrityTokenProviderProvider
) : PlayIntegrityTokenRepository {

    /**
     * Retrieves a classic integrity token.
     *
     * @param nonceBase64 The nonce to bind the integrity token to.
     *                    It must be Base64 encoded in web-safe no-wrap form.
     * @return The integrity token.
     * @throws IllegalStateException If the integrity token is null.
     */
    override suspend fun getTokenClassic(nonceBase64: String): String {
        // Create an instance of a manager for classic requests.
        val integrityManager = IntegrityManagerFactory.create(context.applicationContext)

        // Request the integrity token by providing a nonce.
        val tokenResponse = integrityManager.requestIntegrityToken(
            IntegrityTokenRequest.builder()
                .setNonce(nonceBase64)
                .build()
        ).await()

        return tokenResponse.token() ?: throw IllegalStateException("Integrity token (classic) was null")
    }

    // The cloudProjectNumber argument is kept to match the interface definition,
    // but the StandardIntegrityManager (obtained via provider) is already instantiated with a project number.
    override suspend fun getTokenStandard(cloudProjectNumber: Long, requestHash: String?): String {
        // Obtain StandardIntegrityManager via the provider.
        // The dispatcher is handled internally by the provider.
        val provider = standardIntegrityTokenProviderProvider.get()

        // Prepare the token request builder.
        val requestBuilder = StandardIntegrityManager.StandardIntegrityTokenRequest.builder()

        // Set request hash if provided.
        requestHash?.let {
            requestBuilder.setRequestHash(it)
        }

        // Request the integrity token.
        val tokenResponse = provider.request(
            requestBuilder.build()
        ).await()

        return tokenResponse.token() ?: throw IllegalStateException("Integrity token (standard) was null")
    }
}
