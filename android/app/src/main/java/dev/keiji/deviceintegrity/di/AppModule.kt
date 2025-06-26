package dev.keiji.deviceintegrity.di

import com.jakewharton.retrofit2.converter.kotlinx.serialization.asConverterFactory
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dev.keiji.deviceintegrity.AppInfoProviderImpl
import dev.keiji.deviceintegrity.BuildConfig
import dev.keiji.deviceintegrity.provider.contract.AppInfoProvider
import javax.inject.Named
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Provides
    @Singleton
    fun provideAppInfoProvider(
        impl: AppInfoProviderImpl
    ): AppInfoProvider {
        return impl
    }

    @Provides
    @Named("PlayIntegrityBaseUrl")
    @Singleton
    fun providePlayIntegrityBaseUrl(): String = BuildConfig.PLAY_INTEGRITY_BASE_URL

    @Provides
    @Named("KeyAttestationBaseUrl")
    @Singleton
    fun provideKeyAttestationBaseUrl(): String = BuildConfig.KEY_ATTESTATION_BASE_URL
}
