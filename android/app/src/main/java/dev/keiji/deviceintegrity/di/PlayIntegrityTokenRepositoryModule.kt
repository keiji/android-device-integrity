package dev.keiji.deviceintegrity.di

import android.content.Context
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import dev.keiji.deviceintegrity.provider.contract.StandardIntegrityTokenProviderProvider
import dev.keiji.deviceintegrity.repository.contract.PlayIntegrityTokenRepository
import dev.keiji.deviceintegrity.repository.impl.PlayIntegrityTokenRepositoryImpl
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object PlayIntegrityTokenRepositoryModule {

    @Provides
    @Singleton
    fun providePlayIntegrityTokenRepository(
        @ApplicationContext context: Context, // For classic requests
        standardIntegrityTokenProviderProvider: StandardIntegrityTokenProviderProvider // Provider for standard requests
    ): PlayIntegrityTokenRepository {
        return PlayIntegrityTokenRepositoryImpl(context, standardIntegrityTokenProviderProvider)
    }
}
