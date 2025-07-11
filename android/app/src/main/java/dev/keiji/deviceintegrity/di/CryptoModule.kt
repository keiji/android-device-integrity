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
import com.example.crypto.contract.SharedKeyDerivator
import com.example.crypto.impl.HkdfKeyDerivator
import dev.keiji.deviceintegrity.crypto.contract.Decrypt
import dev.keiji.deviceintegrity.crypto.contract.Encrypt
import dev.keiji.deviceintegrity.crypto.impl.DecryptImpl
import dev.keiji.deviceintegrity.crypto.impl.EcVerifierImpl
import dev.keiji.deviceintegrity.crypto.impl.EncryptImpl
import dev.keiji.deviceintegrity.crypto.impl.RsaSignerImpl
import dev.keiji.deviceintegrity.crypto.impl.RsaVerifierImpl
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object CryptoModule {

    @Provides
    @Singleton
    fun provideSharedKeyDerivator(): SharedKeyDerivator = HkdfKeyDerivator()

    @Provides
    @Singleton
    fun provideEncrypt(): Encrypt = EncryptImpl()

    @Provides
    @Singleton
    fun provideDecrypt(): Decrypt = DecryptImpl()

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
