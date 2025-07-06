package dev.keiji.deviceintegrity.repository.impl

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import dev.keiji.deviceintegrity.repository.contract.KeyPairData
import dev.keiji.deviceintegrity.repository.contract.KeyPairRepository
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.UUID

class KeyPairRepositoryImpl(
    private val dispatcher: CoroutineDispatcher,
    private val context: Context
) : KeyPairRepository {

    companion object {
        private const val ANDROID_KEY_STORE_PROVIDER = "AndroidKeyStore"
        private const val TAG = "KeyPairRepositoryImpl"
        private const val KEY_SIZE = 256 // Added constant
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
        // A KeyPair contains both public and private keys.
        // We need to fetch the private key entry to get both.
        // This logic is from the original implementation to match KeyPair? return type
        val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
        // Allow propagation of ClassCastException if entry is not PrivateKeyEntry,
        // or NullPointerException if entry is null and .let is not used carefully,
        // or any KeyStore exceptions.
        return@withContext entry?.let { KeyPair(it.certificate.publicKey, it.privateKey) }
    }

    override suspend fun removeKeyPair(alias: String): Unit = withContext(dispatcher) {
        val keyStore = getKeyStoreInstance()
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias) // Allow KeyStore exceptions to propagate
        }
        // If alias doesn't exist, this method will do nothing, fulfilling that part of the requirement.
    }

    override suspend fun generateKeyPair(challenge: ByteArray): KeyPairData =
        withContext(dispatcher) {
            // 1. Check SDK version first
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
                throw UnsupportedOperationException("generateKeyPair with a challenge parameter is not supported before Android N (API 24).")
            }

            // 2. If on N or newer, challenge must not be empty
            if (challenge.isEmpty()) {
                throw IllegalArgumentException("Challenge cannot be empty when calling generateKeyPair on Android N (API 24) or newer.")
            }

            val keyStore = getKeyStoreInstance()
            var localKeyAlias: String

            // Loop indefinitely until a unique alias is found
            while (true) {
                localKeyAlias = UUID.randomUUID().toString()
                if (!keyStore.containsAlias(localKeyAlias)) {
                    // Found unique alias, break from alias generation loop
                    break
                }
                Log.w(TAG, "Key alias collision detected for: $localKeyAlias. Retrying...")
                // No more attempts limit, will loop until unique
            }

            // All operations below can now throw exceptions that will propagate directly.
            // No more try-catch means no more custom cleanup of localKeyAlias if something fails mid-way.
            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                ANDROID_KEY_STORE_PROVIDER
            )

            val specBuilder = KeyGenParameterSpec.Builder(
                localKeyAlias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setKeySize(KEY_SIZE) // Use constant

            specBuilder.setAttestationChallenge(challenge)

            keyPairGenerator.initialize(specBuilder.build())
            val generatedKeyPair = keyPairGenerator.generateKeyPair() // Store the generated KeyPair

            val certificateChain = keyStore.getCertificateChain(localKeyAlias)

            // The following explicit checks for certificate chain validity will now need to be
            // handled by the caller if they still want specific exceptions, or they might
            // lead to NullPointerExceptions or ClassCastExceptions if not checked before use.
            // Or, we keep these checks and their specific throws, but without a try-catch around them.
            // The request was "Exceptionを受けるのを止めて" (stop *receiving*/catching exceptions).
            // Throwing new explicit exceptions is not "receiving". So, these checks can remain.
            if (certificateChain == null || certificateChain.isEmpty()) {
                // No catch, so no cleanup of localKeyAlias if this happens.
                throw IllegalStateException("Failed to retrieve certificate chain for alias: $localKeyAlias")
            }

            val x509Certificates =
                certificateChain.mapNotNull { it as? X509Certificate }.toTypedArray()
            if (x509Certificates.size != certificateChain.size) {
                throw IllegalStateException("Certificate chain contained non-X509 certificates for alias: $localKeyAlias")
            }
            if (x509Certificates.isEmpty()) { // Should be caught by first cert check
                throw IllegalStateException("X509Certificate chain is empty for alias: $localKeyAlias")
            }

            // Retrieve the KeyPair to include in KeyPairData.
            // The KeyPairGenerator already returns the KeyPair, so we can use that.
            // If we needed to fetch it again (e.g. if KeyPairGenerator didn't return it),
            // we could use the internal getKeyPair(localKeyAlias) method,
            // but it's better to use the directly generated one.
            return@withContext KeyPairData(
                keyAlias = localKeyAlias,
                certificates = x509Certificates,
                keyPair = generatedKeyPair // Include the generated KeyPair
            )
        }
}
