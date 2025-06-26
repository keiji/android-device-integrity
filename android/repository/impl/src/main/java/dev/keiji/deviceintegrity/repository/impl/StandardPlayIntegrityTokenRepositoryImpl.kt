package dev.keiji.deviceintegrity.repository.impl

import com.google.android.play.core.integrity.StandardIntegrityManager
import dev.keiji.deviceintegrity.provider.contract.StandardIntegrityTokenProviderProvider
import dev.keiji.deviceintegrity.repository.contract.StandardPlayIntegrityTokenRepository
import kotlinx.coroutines.tasks.await
import javax.inject.Inject

/**
 * Implementation of [StandardPlayIntegrityTokenRepository] that uses the Google Play Integrity API.
 */
class StandardPlayIntegrityTokenRepositoryImpl @Inject constructor(
    private val standardIntegrityTokenProviderProvider: StandardIntegrityTokenProviderProvider
) : StandardPlayIntegrityTokenRepository {

    override suspend fun getToken(requestHash: String?): String {
        // Obtain StandardIntegrityManager via the provider.
        val integrityManager = standardIntegrityTokenProviderProvider.get()

        // Prepare the token request builder.
        val requestBuilder = StandardIntegrityManager.StandardIntegrityTokenRequest.builder()

        // Set request hash if provided.
        requestHash?.let {
            requestBuilder.setRequestHash(it)
        }

        // Request the integrity token.
        val tokenResponse = integrityManager.request(
            requestBuilder.build()
        ).await()

        return tokenResponse.token() ?: throw IllegalStateException("Integrity token (standard) was null")
    }
}
