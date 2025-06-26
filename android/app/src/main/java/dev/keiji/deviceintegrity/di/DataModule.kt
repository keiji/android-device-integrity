package dev.keiji.deviceintegrity.di

import android.content.Context
import androidx.datastore.core.DataStore
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import dev.keiji.deviceintegrity.repository.contract.PreferencesRepository
import dev.keiji.deviceintegrity.repository.impl.PreferencesRepositoryImpl
import dev.keiji.deviceintegrity.repository.impl.pb.UserPreferences
import dev.keiji.deviceintegrity.repository.impl.userPreferencesStore
import javax.inject.Named
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object DataModule {

    @Provides
    @Singleton
    fun provideUserPreferencesDataStore(@ApplicationContext context: Context): DataStore<UserPreferences> {
        return context.userPreferencesStore
    }

    @Provides
    @Singleton
    fun providePreferencesRepository(
        @ApplicationContext context: Context,
        dataStore: DataStore<UserPreferences>,
        @Named("PlayIntegrityBaseUrl") playIntegrityBaseUrl: String,
        @Named("KeyAttestationBaseUrl") keyAttestationBaseUrl: String
    ): PreferencesRepository {
        return PreferencesRepositoryImpl(
            context,
            dataStore,
            playIntegrityBaseUrl,
            keyAttestationBaseUrl
        )
    }
}
