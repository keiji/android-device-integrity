package dev.keiji.deviceintegrity.di

import android.content.Context
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import dev.keiji.deviceintegrity.repository.contract.GooglePlayIntegrityTokenProvider
import dev.keiji.deviceintegrity.repository.impl.GooglePlayIntegrityTokenProviderImpl
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object GooglePlayIntegrityTokenProviderModule {

    @Provides
    @Singleton
    fun provideGooglePlayIntegrityTokenProvider(
        @ApplicationContext context: Context
    ): GooglePlayIntegrityTokenProvider {
        return GooglePlayIntegrityTokenProviderImpl(context)
    }
}
