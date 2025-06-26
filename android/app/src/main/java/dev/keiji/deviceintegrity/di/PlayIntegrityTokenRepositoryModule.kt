package dev.keiji.deviceintegrity.di

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dev.keiji.deviceintegrity.repository.contract.ClassicPlayIntegrityTokenRepository
import dev.keiji.deviceintegrity.repository.contract.StandardPlayIntegrityTokenRepository
import dev.keiji.deviceintegrity.repository.impl.ClassicPlayIntegrityTokenRepositoryImpl
import dev.keiji.deviceintegrity.repository.impl.StandardPlayIntegrityTokenRepositoryImpl
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
abstract class PlayIntegrityTokenRepositoryModule {

    @Binds
    @Singleton
    abstract fun bindClassicPlayIntegrityTokenRepository(
        impl: ClassicPlayIntegrityTokenRepositoryImpl
    ): ClassicPlayIntegrityTokenRepository

    @Binds
    @Singleton
    abstract fun bindStandardPlayIntegrityTokenRepository(
        impl: StandardPlayIntegrityTokenRepositoryImpl
    ): StandardPlayIntegrityTokenRepository
}
