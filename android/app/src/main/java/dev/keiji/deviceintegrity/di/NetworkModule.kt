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
import retrofit2.converter.kotlinx.serialization.asConverterFactory
import dev.keiji.deviceintegrity.BuildConfig
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
    fun providePlayIntegrityRetrofit(okHttpClient: OkHttpClient): Retrofit {
        val json = Json { ignoreUnknownKeys = true }
        return Retrofit.Builder()
            .baseUrl(BuildConfig.PLAY_INTEGRITY_BASE_URL)
            .client(okHttpClient)
            .addConverterFactory(json.asConverterFactory("application/json".toMediaType()))
            .build()
    }

    @Provides
    @Singleton
    @KeyAttestation
    fun provideKeyAttestationRetrofit(okHttpClient: OkHttpClient): Retrofit {
        val json = Json { ignoreUnknownKeys = true }
        return Retrofit.Builder()
            .baseUrl(BuildConfig.KEY_ATTESTATION_BASE_URL)
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
