package dev.keiji.deviceintegrity.di

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dev.keiji.deviceintegrity.di.qualifier.KeyAttestation
import dev.keiji.deviceintegrity.di.qualifier.PlayIntegrity
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import retrofit2.Retrofit
import com.jakewharton.retrofit2.converter.kotlinx.serialization.asConverterFactory
import dev.keiji.deviceintegrity.repository.contract.PreferencesRepository
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object NetworkModule {

    @Provides
    @Singleton
    fun provideOkHttpClient(): OkHttpClient {
        return OkHttpClient.Builder()
            .build()
    }

    @Provides
    @Singleton
    @PlayIntegrity
    fun providePlayIntegrityRetrofit(
        okHttpClient: OkHttpClient,
        preferencesRepository: PreferencesRepository
    ): Retrofit {
        val json = Json { ignoreUnknownKeys = true }
        val baseUrl = runBlocking { preferencesRepository.playIntegrityVerifyApiEndpointUrl.first() }
        return Retrofit.Builder()
            .baseUrl(baseUrl)
            .client(okHttpClient)
            .addConverterFactory(json.asConverterFactory("application/json".toMediaType()))
            .build()
    }

    @Provides
    @Singleton
    @KeyAttestation
    fun provideKeyAttestationRetrofit(
        okHttpClient: OkHttpClient,
        preferencesRepository: PreferencesRepository
    ): Retrofit {
        val json = Json { ignoreUnknownKeys = true }
        val baseUrl = runBlocking { preferencesRepository.keyAttestationVerifyApiEndpointUrl.first() }
        return Retrofit.Builder()
            .baseUrl(baseUrl)
            .client(okHttpClient)
            .addConverterFactory(json.asConverterFactory("application/json".toMediaType()))
            .build()
    }

    @Provides
    @Singleton
    fun providePlayIntegrityTokenVerifyApiClient(@PlayIntegrity retrofit: Retrofit): dev.keiji.deviceintegrity.api.playintegrity.PlayIntegrityTokenVerifyApiClient {
        return retrofit.create(dev.keiji.deviceintegrity.api.playintegrity.PlayIntegrityTokenVerifyApiClient::class.java)
    }

    @Provides
    @Singleton
    fun provideKeyAttestationVerifyApiClient(@KeyAttestation retrofit: Retrofit): dev.keiji.deviceintegrity.api.keyattestation.KeyAttestationVerifyApiClient {
        return retrofit.create(dev.keiji.deviceintegrity.api.keyattestation.KeyAttestationVerifyApiClient::class.java)
    }
}
