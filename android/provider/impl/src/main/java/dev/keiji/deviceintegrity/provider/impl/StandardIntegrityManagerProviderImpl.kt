package dev.keiji.deviceintegrity.provider.impl

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.PrepareIntegrityTokenRequest
import com.google.android.play.core.integrity.StandardIntegrityManager
import dagger.hilt.android.qualifiers.ApplicationContext
import dev.keiji.deviceintegrity.provider.contract.qualifier.IoDispatcher // Reverted to provider.contract path
import dev.keiji.deviceintegrity.provider.contract.StandardIntegrityManagerProvider
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.tasks.await
import kotlinx.coroutines.withContext
import timber.log.Timber
import javax.inject.Inject
import javax.inject.Named
import javax.inject.Singleton

@Singleton
class StandardIntegrityManagerProviderImpl @Inject constructor(
    @ApplicationContext private val context: Context,
    @Named("PlayIntegrityCloudProjectNumber") private val cloudProjectNumber: Long,
    @IoDispatcher private val ioDispatcher: CoroutineDispatcher
) : StandardIntegrityManagerProvider {

    @Volatile private var instance: StandardIntegrityManager? = null

    override suspend fun get(): StandardIntegrityManager {
        return instance ?: synchronized(this) {
            instance ?: withContext(ioDispatcher + NonCancellable) {
                Timber.d(
                    "StandardIntegrityManager: Creating and warming up on %s with project number %d",
                    Thread.currentThread().name, // This will show the name of the ioDispatcher's thread
                    cloudProjectNumber
                )
                if (cloudProjectNumber == 0L) {
                    Timber.w("StandardIntegrityManager: PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER is 0L. Standard Integrity API may not work as expected.")
                    // Consider if throwing an exception or returning a specific error state is more appropriate
                    // if cloudProjectNumber being 0L is a critical misconfiguration.
                }
                val manager = IntegrityManagerFactory.createStandard(context, cloudProjectNumber)
                try {
                    manager.prepareIntegrityToken(
                        PrepareIntegrityTokenRequest.builder()
                            .setCloudProjectNumber(cloudProjectNumber)
                            .build()
                    ).await()
                    Timber.i("StandardIntegrityManager: Warmed up successfully.")
                } catch (e: Exception) {
                    Timber.e(e, "StandardIntegrityManager: Failed to warm up.")
                    // Depending on the exception, the manager might still be usable.
                    // Or, you might want to re-throw or handle specific errors.
                }
                manager.also { instance = it }
            }
        }
    }
}
