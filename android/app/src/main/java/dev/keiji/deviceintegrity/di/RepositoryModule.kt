package dev.keiji.deviceintegrity.di

import android.content.Context
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import dev.keiji.deviceintegrity.repository.contract.PreferencesRepository
import dev.keiji.deviceintegrity.repository.impl.PreferencesRepositoryImpl
import javax.inject.Singleton

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
        playIntegrityRepositoryImpl: dev.keiji.repository.impl.PlayIntegrityRepositoryImpl
    ): dev.keiji.repository.contract.PlayIntegrityRepository = playIntegrityRepositoryImpl
}
