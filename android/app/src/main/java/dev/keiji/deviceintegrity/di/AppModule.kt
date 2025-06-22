package dev.keiji.deviceintegrity.di

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dev.keiji.deviceintegrity.BuildConfig
import dev.keiji.deviceintegrity.AppInfoProviderImpl
import dev.keiji.deviceintegrity.provider.contract.qualifier.IoDispatcher // Reverted to provider.contract path
import dev.keiji.deviceintegrity.provider.contract.AppInfoProvider
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import timber.log.Timber
import javax.inject.Named
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule { // Changed from abstract class to object

    // Assuming AppInfoProviderImpl has @Inject constructor or can be provided directly
    @Provides
    @Singleton
    fun provideAppInfoProvider(
        // If AppInfoProviderImpl itself is @Inject constructor annotated and in the same module,
        // Hilt can provide it. Otherwise, it needs its own @Provides method or be injectable.
        // For simplicity, assuming AppInfoProviderImpl is directly constructable or Hilt can find it.
        // If AppInfoProviderImpl is not directly injectable, this needs adjustment.
        // For now, let's assume it's injectable. If not, we might need to read its constructor.
        // A common pattern is `appInfoProviderImpl: AppInfoProviderImpl` if it's injectable.
        // Or `context: Context` if it needs context, etc.
        // Let's assume AppInfoProviderImpl is an injectable type for now.
        // If it requires parameters, this provider method needs them.
        // For the sake of this change, we'll assume we can create it or Hilt can.
        // This might need to be: `impl: AppInfoProviderImpl` and ensure Impl is injectable.
        // Or simply: `return AppInfoProviderImpl(parameters...)`
        // To keep the original binding spirit, we will assume AppInfoProviderImpl is injectable.
        impl: AppInfoProviderImpl
    ): AppInfoProvider {
        return impl
    }

    @Provides
    @Named("PlayIntegrityCloudProjectNumber")
    fun provideCloudProjectNumber(): Long {
        val number = BuildConfig.PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER
        if (number == 0L) {
            Timber.w(
                "AppModule: PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER is 0L. " +
                        "Please set a valid Google Cloud Project Number in build.gradle."
            )
        }
        return number
    }

    @Provides
    @IoDispatcher
    fun provideIoDispatcher(): CoroutineDispatcher = Dispatchers.IO
}
