package dev.keiji.deviceintegrity.provider.impl

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager
import dagger.hilt.android.qualifiers.ApplicationContext
import dev.keiji.deviceintegrity.provider.contract.StandardIntegrityTokenProviderProvider
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.tasks.await
import kotlinx.coroutines.withContext
import timber.log.Timber
import javax.inject.Inject

class StandardIntegrityTokenProviderProviderImpl @Inject constructor(
    @param:ApplicationContext private val context: Context,
    private val cloudProjectNumber: Long,
    private val dispatcher: CoroutineDispatcher
) : StandardIntegrityTokenProviderProvider {

    private val mutex = Mutex()

    @Volatile
    private var instance: StandardIntegrityManager.StandardIntegrityTokenProvider? = null

    override suspend fun get(): StandardIntegrityManager.StandardIntegrityTokenProvider {
        instance?.also {
            return it
        }
        return instance ?: mutex.withLock {
            instance?.also {
                return it
            }
            withContext(dispatcher + NonCancellable) {
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
                val manager = IntegrityManagerFactory.createStandard(context)

                try {
                    val provider = manager.prepareIntegrityToken(
                        StandardIntegrityManager.PrepareIntegrityTokenRequest.builder()
                            .setCloudProjectNumber(cloudProjectNumber)
                            .build()
                    ).await()
                    provider.also { instance = it }

                    Timber.i("StandardIntegrityTokenProvider: Warmed up successfully.")
                    return@withContext provider
                } catch (e: Exception) {
                    Timber.e(e, "StandardIntegrityTokenProvider: Failed to warm up.")
                    throw e
                }
            }
        }
    }

    override fun invalidate() {
        instance = null
    }
}
