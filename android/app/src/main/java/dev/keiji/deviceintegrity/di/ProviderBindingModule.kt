package dev.keiji.deviceintegrity.di

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dev.keiji.deviceintegrity.provider.contract.StandardIntegrityManagerProvider
import dev.keiji.deviceintegrity.provider.impl.StandardIntegrityManagerProviderImpl
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
abstract class ProviderBindingModule {

    @Binds
    @Singleton
    abstract fun bindStandardIntegrityManagerProvider(
        impl: StandardIntegrityManagerProviderImpl
    ): StandardIntegrityManagerProvider
}
