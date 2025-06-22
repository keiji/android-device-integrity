package dev.keiji.deviceintegrity.di

import android.content.Context
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import dev.keiji.deviceintegrity.provider.contract.StandardIntegrityTokenProviderProvider
import dev.keiji.deviceintegrity.repository.contract.GooglePlayIntegrityTokenRepository
import dev.keiji.deviceintegrity.repository.impl.GooglePlayIntegrityTokenRepositoryImpl
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object GooglePlayIntegrityTokenRepositoryModule {

    @Provides
    @Singleton
    fun provideGooglePlayIntegrityTokenRepository(
        @ApplicationContext context: Context, // For classic requests
        standardIntegrityTokenProviderProvider: StandardIntegrityTokenProviderProvider // Provider for standard requests
    ): GooglePlayIntegrityTokenRepository {
        return GooglePlayIntegrityTokenRepositoryImpl(context, standardIntegrityTokenProviderProvider)
    }
}
