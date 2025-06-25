package dev.keiji.deviceintegrity.di

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dev.keiji.deviceintegrity.di.qualifier.KeyAttestation
import dev.keiji.deviceintegrity.di.qualifier.PlayIntegrity
import okhttp3.OkHttpClient
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object NetworkModule {

    private const val PLAY_INTEGRITY_BASE_URL = "https://playintegrity.googleapis.com/"
    private const val KEY_ATTESTATION_BASE_URL = "https://keyattestation.googleapis.com/"

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
        return Retrofit.Builder()
            .baseUrl(PLAY_INTEGRITY_BASE_URL)
            .client(okHttpClient)
            .addConverterFactory(MoshiConverterFactory.create())
            .build()
    }

    @Provides
    @Singleton
    @KeyAttestation
    fun provideKeyAttestationRetrofit(okHttpClient: OkHttpClient): Retrofit {
        return Retrofit.Builder()
            .baseUrl(KEY_ATTESTATION_BASE_URL)
            .client(okHttpClient)
            .addConverterFactory(MoshiConverterFactory.create())
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
