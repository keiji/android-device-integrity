package dev.keiji.deviceintegrity.di

import android.content.Context
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import dev.keiji.deviceintegrity.repository.contract.PreferencesRepository
import dev.keiji.deviceintegrity.repository.impl.PreferencesRepositoryImpl
import dev.keiji.deviceintegrity.repository.contract.KeyPairRepository
import dev.keiji.deviceintegrity.repository.contract.PlayIntegrityRepository
import dev.keiji.deviceintegrity.repository.impl.KeyPairRepositoryImpl
import dev.keiji.deviceintegrity.repository.impl.PlayIntegrityRepositoryImpl
import kotlinx.coroutines.Dispatchers
import javax.inject.Singleton
import dev.keiji.deviceintegrity.api.keyattestation.KeyAttestationVerifyApiClient
import dev.keiji.deviceintegrity.provider.contract.DeviceSecurityStateProvider
import dev.keiji.deviceintegrity.repository.contract.KeyAttestationRepository
import dev.keiji.deviceintegrity.repository.impl.KeyAttestationRepositoryImpl

@Module
@InstallIn(SingletonComponent::class)
object RepositoryModule {

    @Singleton
    @Provides
    fun providePreferencesRepository(
        @ApplicationContext context: Context
    ): PreferencesRepository = PreferencesRepositoryImpl(context)

    @Singleton
    @Provides
    fun providePlayIntegrityRepository(
        playIntegrityRepositoryImpl: PlayIntegrityRepositoryImpl
    ): PlayIntegrityRepository = playIntegrityRepositoryImpl

    @Provides
    @Singleton
    fun provideKeyPairRepository(
        deviceSecurityStateProvider: DeviceSecurityStateProvider
    ): KeyPairRepository {
        return KeyPairRepositoryImpl(Dispatchers.IO, deviceSecurityStateProvider)
    }

    @Provides
    @Singleton
    fun provideKeyAttestationRepository(
        apiClient: KeyAttestationVerifyApiClient
    ): KeyAttestationRepository {
        return KeyAttestationRepositoryImpl(apiClient)
    }
}
