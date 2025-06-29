package dev.keiji.repository.impl.di

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dev.keiji.repository.contract.PlayIntegrityRepository
import dev.keiji.repository.impl.PlayIntegrityRepositoryImpl
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
abstract class RepositoryModule {

    @Binds
    @Singleton
    abstract fun bindPlayIntegrityRepository(
        playIntegrityRepositoryImpl: PlayIntegrityRepositoryImpl
    ): PlayIntegrityRepository
}
