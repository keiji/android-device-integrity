package dev.keiji.deviceintegrity.di

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dev.keiji.deviceintegrity.AppInfoProviderImpl
import dev.keiji.deviceintegrity.provider.contract.AppInfoProvider
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule { // Changed from abstract class to object

    // Assuming AppInfoProviderImpl has @Inject constructor or can be provided directly
    @Provides
    @Singleton
    fun provideAppInfoProvider(
        impl: AppInfoProviderImpl
    ): AppInfoProvider {
        return impl
    }
}
