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
        // Early exit if attestation is requested on an unsupported OS version
        if (challenge.isNotEmpty() && Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            throw UnsupportedOperationException("Key attestation with a challenge is not supported before Android N (API 24).")
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

            // Only set attestation challenge if API is N+ AND challenge is provided.
            // The initial check already handles if challenge.isNotEmpty() on pre-N.
            // So, if we are here and challenge is not empty, it's N+
            if (challenge.isNotEmpty()) { // Redundant check if Build.VERSION.SDK_INT >= N is already implied, but safe.
                 if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) { // Explicitly keep for clarity
                    specBuilder.setAttestationChallenge(challenge)
                }
            }

            keyPairGenerator.initialize(specBuilder.build())
                    keyPairGenerator.generateKeyPair() // Key pair is generated and stored

                    // Fetch the certificate chain
                    val certificateChain = keyStore.getCertificateChain(localKeyAlias)

                    if (certificateChain == null || certificateChain.isEmpty()) {
                        Log.e(TAG, "Failed to retrieve certificate chain for alias: $localKeyAlias after generation.")
                        throw IllegalStateException("Failed to retrieve certificate chain for alias: $localKeyAlias")
                    }

                    // Cast to Array<X509Certificate>
                    val x509Certificates = certificateChain.mapNotNull { it as? X509Certificate }.toTypedArray()

                    if (x509Certificates.size != certificateChain.size) {
                         Log.e(TAG, "Not all certificates in the chain were X509Certificates for alias: $localKeyAlias")
                         throw IllegalStateException("Certificate chain contained non-X509 certificates for alias: $localKeyAlias")
                    }

                    if (x509Certificates.isEmpty()){
                        Log.e(TAG, "X509Certificate chain is empty for alias: $localKeyAlias")
                        throw IllegalStateException("X509Certificate chain is empty for alias: $localKeyAlias")
                    }

                    return@withContext KeyPairData(keyAlias = localKeyAlias, certificates = x509Certificates)
                } catch (e: Exception) {
                    Log.e(TAG, "Error generating key pair or fetching certificate chain for alias: $localKeyAlias", e)
                    // Clean up the alias if key generation partially succeeded but cert chain failed or other error
                    if (keyStore.containsAlias(localKeyAlias)) {
                         try { keyStore.deleteEntry(localKeyAlias) } catch (deleteEx: Exception) { Log.e(TAG, "Failed to delete partial key for alias: $localKeyAlias", deleteEx) }
                    }
                    throw e
                }
    }
}
