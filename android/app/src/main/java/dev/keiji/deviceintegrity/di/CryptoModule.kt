package dev.keiji.deviceintegrity.di

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dev.keiji.deviceintegrity.crypto.contract.Signer
import dev.keiji.deviceintegrity.crypto.contract.Verifier
import dev.keiji.deviceintegrity.crypto.contract.qualifier.EC
import dev.keiji.deviceintegrity.crypto.contract.qualifier.RSA
import dev.keiji.deviceintegrity.crypto.impl.EcSignerImpl
import dev.keiji.deviceintegrity.crypto.impl.EcVerifierImpl
import dev.keiji.deviceintegrity.crypto.impl.RsaSignerImpl
import dev.keiji.deviceintegrity.crypto.impl.RsaVerifierImpl
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object CryptoModule {

    @EC
    @Provides
    @Singleton
    fun provideEcSigner(): Signer = EcSignerImpl()

    @EC
    @Provides
    @Singleton
    fun provideEcVerifier(): Verifier = EcVerifierImpl()

    @RSA
    @Provides
    @Singleton
    fun provideRsaSigner(): Signer = RsaSignerImpl()

    @RSA
    @Provides
    @Singleton
    fun provideRsaVerifier(): Verifier = RsaVerifierImpl()
}
