package dev.keiji.deviceintegrity.provider.impl.di

import android.content.Context
import dev.keiji.deviceintegrity.provider.contract.GoogleIntegrityTokenProvider
import dev.keiji.deviceintegrity.provider.impl.GoogleIntegrityTokenProviderImpl
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object GoogleIntegrityTokenProviderModule {

    @Provides
    @Singleton
    fun provideGoogleIntegrityTokenProvider(
        @ApplicationContext context: Context
    ): GoogleIntegrityTokenProvider {
        return GoogleIntegrityTokenProviderImpl(context)
    }
}
