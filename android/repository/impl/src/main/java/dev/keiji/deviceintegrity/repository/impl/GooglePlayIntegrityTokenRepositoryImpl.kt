package dev.keiji.deviceintegrity.repository.impl

import android.content.Context
import dev.keiji.deviceintegrity.repository.contract.GooglePlayIntegrityTokenRepository
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.tasks.await
import javax.inject.Inject // Added for Hilt constructor injection, though Context is provided by Hilt module

/**
 * Implementation of [GooglePlayIntegrityTokenRepository] that uses the Google Play Integrity API.
 */
class GooglePlayIntegrityTokenRepositoryImpl @Inject constructor( // Mark constructor for Hilt if it's directly injected,
                                                     // but here it will be constructed by a Hilt module.
    private val context: Context
) : GooglePlayIntegrityTokenRepository {

    override suspend fun getToken(nonce: String): String {
        // Create an instance of a manager.
        val integrityManager = IntegrityManagerFactory.create(context.applicationContext)

        // Request the integrity token by providing a nonce.
        val tokenResponse = integrityManager.requestIntegrityToken(
            IntegrityTokenRequest.builder()
                .setNonce(nonce)
                .build()
        ).await() // Using kotlinx-coroutines-play-services to await the Task

        // Check if the token is present, though the API docs suggest it should be.
        // If token() can return null and the interface expects non-null String,
        // appropriate error handling or a different return type (String?) would be needed.
        // For now, assuming token() returns a non-null String as per typical Integrity API usage.
        return tokenResponse.token() ?: throw IllegalStateException("Integrity token was null")
    }
}
