package com.sample.android.trivialdrivesample.di

import android.content.Context
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import dev.keiji.deviceintegrity.provider.contract.GooglePlayIntegrityTokenProvider
import dev.keiji.deviceintegrity.provider.impl.di.GooglePlayIntegrityTokenProviderModule
import javax.inject.Singleton

@Module(includes = [GooglePlayIntegrityTokenProviderModule::class])
@InstallIn(SingletonComponent::class)
object AppIntegrityModule {

    // This module doesn't need to provide GooglePlayIntegrityTokenProvider directly
    // if GooglePlayIntegrityTokenProviderModule is included and already provides it.
    // Hilt will find the provider from the included module.
}
