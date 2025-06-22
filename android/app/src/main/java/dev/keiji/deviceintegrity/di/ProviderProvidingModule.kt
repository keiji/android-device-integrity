package dev.keiji.deviceintegrity.di

import android.content.Context
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import dev.keiji.deviceintegrity.BuildConfig
import dev.keiji.deviceintegrity.provider.contract.StandardIntegrityTokenProviderProvider
import dev.keiji.deviceintegrity.provider.impl.StandardIntegrityTokenProviderProviderImpl
import kotlinx.coroutines.Dispatchers
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object ProviderProvidingModule {

    @Singleton
    @Provides
    fun provideStandardIntegrityManagerProvider(
        @ApplicationContext context: Context,
    ): StandardIntegrityTokenProviderProvider {
        return StandardIntegrityTokenProviderProviderImpl(
            context = context,
            cloudProjectNumber = BuildConfig.PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER,
            dispatcher = Dispatchers.IO,
        )
    }
}
