package dev.keiji.deviceintegrity.provider.contract

import com.google.android.play.core.integrity.StandardIntegrityManager

/**
 * Interface for providing a warmed-up StandardIntegrityTokenProvider instance.
 */
interface StandardIntegrityTokenProviderProvider {
    /**
     * Gets a StandardIntegrityTokenProvider instance.
     * The instance will be created and warmed up on the first call, using an internally defined dispatcher.
     * Subsequent calls will return the cached instance.
     *
     * @return A StandardIntegrityTokenProvider instance.
     */
    suspend fun get(): StandardIntegrityManager.StandardIntegrityTokenProvider
}
