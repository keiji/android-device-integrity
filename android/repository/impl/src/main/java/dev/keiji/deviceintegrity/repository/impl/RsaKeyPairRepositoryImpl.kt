package dev.keiji.deviceintegrity.repository.impl

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import dev.keiji.deviceintegrity.repository.contract.KeyPairData
import dev.keiji.deviceintegrity.repository.contract.RsaKeyPairRepository
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.UUID
import javax.inject.Inject

class RsaKeyPairRepositoryImpl @Inject constructor(
    @IoDispatcher private val dispatcher: CoroutineDispatcher,
    private val context: Context
) : RsaKeyPairRepository {

    companion object {
        private const val ANDROID_KEY_STORE_PROVIDER = "AndroidKeyStore"
        private const val TAG = "RsaKeyPairRepositoryImpl"
        private const val KEY_SIZE = 2048
    }

    private fun getKeyStoreInstance(): KeyStore {
        return KeyStore.getInstance(ANDROID_KEY_STORE_PROVIDER).apply {
            load(null)
        }
    }

    override suspend fun getKeyPair(alias: String): KeyPair? = withContext(dispatcher) {
        val keyStore = getKeyStoreInstance()
        if (!keyStore.containsAlias(alias)) {
            return@withContext null
        }
        val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
        return@withContext entry?.let { KeyPair(it.certificate.publicKey, it.privateKey) }
    }

    override suspend fun removeKeyPair(alias: String): Unit = withContext(dispatcher) {
        val keyStore = getKeyStoreInstance()
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias)
        }
    }

    override suspend fun generateKeyPair(challenge: ByteArray): KeyPairData =
        withContext(dispatcher) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
                throw UnsupportedOperationException("generateKeyPair with a challenge parameter is not supported before Android N (API 24).")
            }

            if (challenge.isEmpty()) {
                throw IllegalArgumentException("Challenge cannot be empty when calling generateKeyPair on Android N (API 24) or newer.")
            }

            val keyStore = getKeyStoreInstance()
            var localKeyAlias: String

            while (true) {
                localKeyAlias = UUID.randomUUID().toString()
                if (!keyStore.containsAlias(localKeyAlias)) {
                    break
                }
                Log.w(TAG, "Key alias collision detected for: $localKeyAlias. Retrying...")
            }

            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA,
                ANDROID_KEY_STORE_PROVIDER
            )

            val specBuilder = KeyGenParameterSpec.Builder(
                localKeyAlias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setKeySize(KEY_SIZE)

            specBuilder.setAttestationChallenge(challenge)

            keyPairGenerator.initialize(specBuilder.build())
            val generatedKeyPair = keyPairGenerator.generateKeyPair()

            val certificateChain = keyStore.getCertificateChain(localKeyAlias)

            if (certificateChain == null || certificateChain.isEmpty()) {
                throw IllegalStateException("Failed to retrieve certificate chain for alias: $localKeyAlias")
            }

            val x509Certificates =
                certificateChain.mapNotNull { it as? X509Certificate }.toTypedArray()
            if (x509Certificates.size != certificateChain.size) {
                throw IllegalStateException("Certificate chain contained non-X509 certificates for alias: $localKeyAlias")
            }
            if (x509Certificates.isEmpty()) {
                throw IllegalStateException("X509Certificate chain is empty for alias: $localKeyAlias")
            }

            return@withContext KeyPairData(
                keyAlias = localKeyAlias,
                certificates = x509Certificates,
                keyPair = generatedKeyPair
            )
        }
}
