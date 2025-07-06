package dev.keiji.deviceintegrity.di

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dev.keiji.deviceintegrity.di.qualifier.EC
import dev.keiji.deviceintegrity.crypto.contract.Signer
import dev.keiji.deviceintegrity.crypto.contract.Verifier
import dev.keiji.deviceintegrity.crypto.impl.EcSignerImpl
import dev.keiji.deviceintegrity.crypto.impl.EcVerifierImpl

import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
class CryptoModule {

    @EC
    @Provides
    @Singleton // Added @Singleton here as well
    fun provideEcSigner(): Signer = EcSignerImpl()

    @EC
    @Provides
    @Singleton // Added @Singleton here as well
    fun provideEcVerifier(): Verifier = EcVerifierImpl()
}
