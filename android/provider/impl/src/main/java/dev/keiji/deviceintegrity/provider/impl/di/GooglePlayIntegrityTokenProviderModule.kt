package dev.keiji.deviceintegrity.provider.impl.di

import android.content.Context
import dev.keiji.deviceintegrity.provider.contract.GooglePlayIntegrityTokenProvider
import dev.keiji.deviceintegrity.provider.impl.GooglePlayIntegrityTokenProviderImpl
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
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
