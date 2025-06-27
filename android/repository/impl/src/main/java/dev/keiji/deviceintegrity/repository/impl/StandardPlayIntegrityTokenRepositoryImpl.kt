package dev.keiji.deviceintegrity.repository.impl

import android.util.Base64
import com.google.android.play.core.integrity.StandardIntegrityManager
import dev.keiji.deviceintegrity.provider.contract.StandardIntegrityTokenProviderProvider
import dev.keiji.deviceintegrity.repository.contract.StandardPlayIntegrityTokenRepository
import kotlinx.coroutines.tasks.await
import java.security.MessageDigest
import javax.inject.Inject

/**
 * Implementation of [StandardPlayIntegrityTokenRepository] that uses the Google Play Integrity API.
 */
class StandardPlayIntegrityTokenRepositoryImpl @Inject constructor(
    private val standardIntegrityTokenProviderProvider: StandardIntegrityTokenProviderProvider
) : StandardPlayIntegrityTokenRepository {

    override suspend fun getToken(contentToBind: String?): String { // Changed argument name
        // Obtain StandardIntegrityManager via the provider.
        val integrityManager = standardIntegrityTokenProviderProvider.get()

        // Prepare the token request builder.
        val requestBuilder = StandardIntegrityManager.StandardIntegrityTokenRequest.builder()

        contentToBind?.let { content ->
            // Hash and Base64URL encode the content
            val hashedBytes = MessageDigest.getInstance("SHA-256").digest(content.toByteArray(Charsets.UTF_8))
            val requestHashSetBySdk = Base64.encodeToString(hashedBytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            requestBuilder.setRequestHash(requestHashSetBySdk)
        }

        // Request the integrity token.
        val tokenResponse = integrityManager.request(
            requestBuilder.build()
        ).await()

        return tokenResponse.token() ?: throw IllegalStateException("Integrity token (standard) was null")
    }
}
