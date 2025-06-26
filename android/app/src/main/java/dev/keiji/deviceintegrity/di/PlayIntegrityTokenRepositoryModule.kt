package dev.keiji.deviceintegrity.di

import android.content.Context
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import dev.keiji.deviceintegrity.provider.contract.StandardIntegrityTokenProviderProvider
import dev.keiji.deviceintegrity.repository.contract.ClassicPlayIntegrityTokenRepository
import dev.keiji.deviceintegrity.repository.contract.StandardPlayIntegrityTokenRepository
import dev.keiji.deviceintegrity.repository.impl.ClassicPlayIntegrityTokenRepositoryImpl
import dev.keiji.deviceintegrity.repository.impl.StandardPlayIntegrityTokenRepositoryImpl
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object PlayIntegrityTokenRepositoryModule {

    @Provides
    @Singleton
    fun provideClassicPlayIntegrityTokenRepository(
        @ApplicationContext context: Context
    ): ClassicPlayIntegrityTokenRepository {
        return ClassicPlayIntegrityTokenRepositoryImpl(context)
    }

    @Provides
    @Singleton
    fun provideStandardPlayIntegrityTokenRepository(
        standardIntegrityTokenProviderProvider: StandardIntegrityTokenProviderProvider
    ): StandardPlayIntegrityTokenRepository {
        return StandardPlayIntegrityTokenRepositoryImpl(standardIntegrityTokenProviderProvider)
    }
}
