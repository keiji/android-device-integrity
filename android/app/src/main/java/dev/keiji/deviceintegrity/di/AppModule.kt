package dev.keiji.deviceintegrity.di

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dev.keiji.deviceintegrity.AppInfoProviderImpl
import dev.keiji.deviceintegrity.provider.contract.AppInfoProvider
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
abstract class AppModule {

    @Binds
    @Singleton
    abstract fun bindAppInfoProvider(
        appInfoProviderImpl: AppInfoProviderImpl
    ): AppInfoProvider
}
