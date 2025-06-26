package dev.keiji.deviceintegrity.repository.impl

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import dev.keiji.deviceintegrity.repository.contract.ClassicPlayIntegrityTokenRepository
import kotlinx.coroutines.tasks.await
import javax.inject.Inject

/**
 * Implementation of [ClassicPlayIntegrityTokenRepository] that uses the Google Play Integrity API.
 */
class ClassicPlayIntegrityTokenRepositoryImpl @Inject constructor(
    private val context: Context
) : ClassicPlayIntegrityTokenRepository {

    /**
     * Retrieves a classic integrity token.
     *
     * @param nonceBase64 The nonce to bind the integrity token to.
     *                    It must be Base64 encoded in web-safe no-wrap form.
     * @return The integrity token.
     * @throws IllegalStateException If the integrity token is null.
     */
    override suspend fun getToken(nonceBase64: String): String {
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
}
