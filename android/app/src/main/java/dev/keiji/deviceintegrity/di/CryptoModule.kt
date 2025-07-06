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

@Module
@InstallIn(SingletonComponent::class)
object CryptoModule {

    @EC
    @Provides
    fun provideEcSigner(): Signer = EcSignerImpl()

    @EC
    @Provides
    fun provideEcVerifier(): Verifier = EcVerifierImpl()
}
