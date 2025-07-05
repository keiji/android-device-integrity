package dev.keiji.deviceintegrity.repository.impl

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import dev.keiji.deviceintegrity.repository.KeyPairData
import dev.keiji.deviceintegrity.repository.KeyPairRepository
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
        try {
            val keyStore = getKeyStoreInstance()
            if (!keyStore.containsAlias(alias)) {
                return@withContext null
            }
            // A KeyPair contains both public and private keys.
            // We need to fetch the private key entry to get both.
            // This logic is from the original implementation to match KeyPair? return type
            val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            return@withContext entry?.let { KeyPair(it.certificate.publicKey, it.privateKey) }
        } catch (e: Exception) {
            Log.e(TAG, "Error retrieving key pair for alias: $alias", e)
            return@withContext null
        }
    }

    override suspend fun removeKeyPair(alias: String): Unit = withContext(dispatcher) {
        try {
            val keyStore = getKeyStoreInstance()
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }
        } catch (e: Exception) {
            // Corrected syntax error: Log.e was outside the catch block in the prompt's new code
            Log.e(TAG, "Error removing key entry for alias: $alias", e)
            // As per requirement, do not throw exception.
        }
    }

    override suspend fun generateKeyPair(challenge: ByteArray): KeyPairData = withContext(dispatcher) {
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

        try {
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

            // At this point, SDK is N+ and challenge is not empty, so setAttestationChallenge can be called.
            specBuilder.setAttestationChallenge(challenge)

            keyPairGenerator.initialize(specBuilder.build())
            keyPairGenerator.generateKeyPair()

            val certificateChain = keyStore.getCertificateChain(localKeyAlias)
            if (certificateChain == null || certificateChain.isEmpty()) {
                Log.e(TAG, "Failed to retrieve certificate chain for alias: $localKeyAlias after generation.")
                // Attempt to clean up the generated alias if cert chain fails
                try { keyStore.deleteEntry(localKeyAlias) } catch (deleteEx: Exception) { Log.e(TAG, "Failed to delete partial key during cert chain failure for alias: $localKeyAlias", deleteEx) }
                throw IllegalStateException("Failed to retrieve certificate chain for alias: $localKeyAlias")
            }

            val x509Certificates = certificateChain.mapNotNull { it as? X509Certificate }.toTypedArray()
            if (x509Certificates.size != certificateChain.size) {
                Log.e(TAG, "Not all certificates in the chain were X509Certificates for alias: $localKeyAlias")
                try { keyStore.deleteEntry(localKeyAlias) } catch (deleteEx: Exception) { Log.e(TAG, "Failed to delete partial key during cert type mismatch for alias: $localKeyAlias", deleteEx) }
                throw IllegalStateException("Certificate chain contained non-X509 certificates for alias: $localKeyAlias")
            }
            if (x509Certificates.isEmpty()){ // Should be caught by (certificateChain == null || certificateChain.isEmpty()) already but good for defense
                Log.e(TAG, "X509Certificate chain is empty for alias: $localKeyAlias")
                try { keyStore.deleteEntry(localKeyAlias) } catch (deleteEx: Exception) { Log.e(TAG, "Failed to delete partial key for empty X509 cert chain for alias: $localKeyAlias", deleteEx) }
                throw IllegalStateException("X509Certificate chain is empty for alias: $localKeyAlias")
            }

            return@withContext KeyPairData(keyAlias = localKeyAlias, certificates = x509Certificates)
        } catch (e: Exception) {
            // Catching exceptions from KeyPairGenerator, KeyStore operations, or our explicit throws for cert issues
            Log.e(TAG, "Error generating key pair or fetching certificate chain for alias: $localKeyAlias", e)
            // Attempt to clean up the alias if it exists and the exception was not one of our early throws
            if (e !is UnsupportedOperationException && e !is IllegalArgumentException && keyStore.containsAlias(localKeyAlias)) {
                 try { keyStore.deleteEntry(localKeyAlias) } catch (deleteEx: Exception) { Log.e(TAG, "Failed to delete partial key for alias: $localKeyAlias during general exception", deleteEx) }
            }
            throw e // Rethrow the original exception
        }
    }
}
