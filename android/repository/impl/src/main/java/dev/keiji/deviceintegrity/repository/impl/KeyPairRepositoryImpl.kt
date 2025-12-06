package dev.keiji.deviceintegrity.repository.impl

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import dev.keiji.deviceintegrity.provider.contract.DeviceSecurityStateProvider
import dev.keiji.deviceintegrity.repository.contract.KeyPairData
import dev.keiji.deviceintegrity.repository.contract.KeyPairRepository
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.UUID
import javax.inject.Inject

class KeyPairRepositoryImpl @Inject constructor(
    private val dispatcher: CoroutineDispatcher,
    private val deviceSecurityStateProvider: DeviceSecurityStateProvider,
) : KeyPairRepository {

    companion object {
        private const val ANDROID_KEY_STORE_PROVIDER = "AndroidKeyStore"
        private const val TAG = "KeyPairRepositoryImpl"
        private const val EC_KEY_SIZE = 256
        private const val RSA_KEY_SIZE = 2048
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

    override suspend fun generateEcKeyPair(
        challenge: ByteArray,
        preferStrongBox: Boolean,
        includeIdAttestation: Boolean
    ): KeyPairData =
        withContext(dispatcher) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
                throw UnsupportedOperationException("generateEcKeyPair with a challenge parameter is not supported before Android N (API 24).")
            }
            if (challenge.isEmpty()) {
                throw IllegalArgumentException("Challenge cannot be empty when calling generateEcKeyPair on Android N (API 24) or newer.")
            }

            val keyStore = getKeyStoreInstance()
            var localKeyAlias: String
            while (true) {
                localKeyAlias = UUID.randomUUID().toString()
                if (!keyStore.containsAlias(localKeyAlias)) {
                    break
                }
                Log.w(TAG, "EC Key alias collision detected for: $localKeyAlias. Retrying...")
            }

            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                ANDROID_KEY_STORE_PROVIDER
            )

            val specBuilder = KeyGenParameterSpec.Builder(
                localKeyAlias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setKeySize(EC_KEY_SIZE)
                .setAttestationChallenge(challenge)

            if (deviceSecurityStateProvider.isDevicePropertiesAttestationSupported) {
                @SuppressLint("NewApi")
                specBuilder.setDevicePropertiesAttestationIncluded(includeIdAttestation)
            }

            if (preferStrongBox && deviceSecurityStateProvider.hasStrongBox) {
                @SuppressLint("NewApi")
                specBuilder.setIsStrongBoxBacked(true)
            }

            keyPairGenerator.initialize(specBuilder.build())
            val generatedKeyPair = keyPairGenerator.generateKeyPair()

            val certificateChain = keyStore.getCertificateChain(localKeyAlias)
            if (certificateChain == null || certificateChain.isEmpty()) {
                try { keyStore.deleteEntry(localKeyAlias) } catch (e: Exception) { Log.e(TAG, "Failed to cleanup orphaned EC key: $localKeyAlias", e) }
                throw IllegalStateException("Failed to retrieve EC certificate chain for alias: $localKeyAlias")
            }

            val x509Certificates = certificateChain.mapNotNull { it as? X509Certificate }.toTypedArray()
            if (x509Certificates.size != certificateChain.size || x509Certificates.isEmpty()) {
                 try { keyStore.deleteEntry(localKeyAlias) } catch (e: Exception) { Log.e(TAG, "Failed to cleanup EC key due to cert issue: $localKeyAlias", e) }
                throw IllegalStateException("EC Certificate chain contained non-X509 or empty certificates for alias: $localKeyAlias")
            }

            return@withContext KeyPairData(
                keyAlias = localKeyAlias,
                certificates = x509Certificates,
                keyPair = generatedKeyPair
            )
        }

    override suspend fun generateRsaKeyPair(
        challenge: ByteArray,
        preferStrongBox: Boolean,
        includeIdAttestation: Boolean
    ): KeyPairData =
        withContext(dispatcher) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
                throw UnsupportedOperationException("generateRsaKeyPair with a challenge parameter is not supported before Android N (API 24).")
            }
            if (challenge.isEmpty()) {
                throw IllegalArgumentException("Challenge cannot be empty when calling generateRsaKeyPair on Android N (API 24) or newer.")
            }

            val keyStore = getKeyStoreInstance()
            var localKeyAlias: String
            while (true) {
                localKeyAlias = UUID.randomUUID().toString()
                if (!keyStore.containsAlias(localKeyAlias)) {
                    break
                }
                Log.w(TAG, "RSA Key alias collision detected for: $localKeyAlias. Retrying...")
            }

            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA,
                ANDROID_KEY_STORE_PROVIDER
            )

            val specBuilder = KeyGenParameterSpec.Builder(
                localKeyAlias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setKeySize(RSA_KEY_SIZE)
                .setAttestationChallenge(challenge)

            if (deviceSecurityStateProvider.isDevicePropertiesAttestationSupported) {
                @SuppressLint("NewApi")
                specBuilder.setDevicePropertiesAttestationIncluded(includeIdAttestation)
            }

            if (preferStrongBox && deviceSecurityStateProvider.hasStrongBox) {
                @SuppressLint("NewApi")
                specBuilder.setIsStrongBoxBacked(true)
            }

            keyPairGenerator.initialize(specBuilder.build())
            val generatedKeyPair = keyPairGenerator.generateKeyPair()

            val certificateChain = keyStore.getCertificateChain(localKeyAlias)
            if (certificateChain == null || certificateChain.isEmpty()) {
                try { keyStore.deleteEntry(localKeyAlias) } catch (e: Exception) { Log.e(TAG, "Failed to cleanup orphaned RSA key: $localKeyAlias", e) }
                throw IllegalStateException("Failed to retrieve RSA certificate chain for alias: $localKeyAlias")
            }

            val x509Certificates = certificateChain.mapNotNull { it as? X509Certificate }.toTypedArray()
            if (x509Certificates.size != certificateChain.size || x509Certificates.isEmpty()) {
                try { keyStore.deleteEntry(localKeyAlias) } catch (e: Exception) { Log.e(TAG, "Failed to cleanup RSA key due to cert issue: $localKeyAlias", e) }
                throw IllegalStateException("RSA Certificate chain contained non-X509 or empty certificates for alias: $localKeyAlias")
            }

            return@withContext KeyPairData(
                keyAlias = localKeyAlias,
                certificates = x509Certificates,
                keyPair = generatedKeyPair
            )
        }

    override suspend fun generateEcdhKeyPair(
        challenge: ByteArray,
        preferStrongBox: Boolean,
        includeIdAttestation: Boolean
    ): KeyPairData =
        withContext(dispatcher) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
                throw UnsupportedOperationException("generateEcdhKeyPair with a challenge parameter is not supported before Android S (API 31).")
            }
            if (challenge.isEmpty()) {
                throw IllegalArgumentException("Challenge cannot be empty when calling generateEcdhKeyPair on Android S (API 31) or newer.")
            }

            val keyStore = getKeyStoreInstance()
            var localKeyAlias: String
            while (true) {
                localKeyAlias = UUID.randomUUID().toString()
                if (!keyStore.containsAlias(localKeyAlias)) {
                    break
                }
                Log.w(TAG, "ECDH Key alias collision detected for: $localKeyAlias. Retrying...")
            }

            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                ANDROID_KEY_STORE_PROVIDER
            )

            val specBuilder = KeyGenParameterSpec.Builder(
                localKeyAlias,
                KeyProperties.PURPOSE_AGREE_KEY
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setKeySize(EC_KEY_SIZE)
                .setAttestationChallenge(challenge)

            @SuppressLint("NewApi")
            specBuilder.setDevicePropertiesAttestationIncluded(includeIdAttestation)

            if (preferStrongBox && deviceSecurityStateProvider.hasStrongBox) {
                @SuppressLint("NewApi")
                specBuilder.setIsStrongBoxBacked(true)
            }

            keyPairGenerator.initialize(specBuilder.build())
            val generatedKeyPair = keyPairGenerator.generateKeyPair()

            val certificateChain = keyStore.getCertificateChain(localKeyAlias)
            if (certificateChain == null || certificateChain.isEmpty()) {
                try { keyStore.deleteEntry(localKeyAlias) } catch (e: Exception) { Log.e(TAG, "Failed to cleanup orphaned ECDH key: $localKeyAlias", e) }
                throw IllegalStateException("Failed to retrieve ECDH certificate chain for alias: $localKeyAlias")
            }

            val x509Certificates = certificateChain.mapNotNull { it as? X509Certificate }.toTypedArray()
            if (x509Certificates.size != certificateChain.size || x509Certificates.isEmpty()) {
                 try { keyStore.deleteEntry(localKeyAlias) } catch (e: Exception) { Log.e(TAG, "Failed to cleanup ECDH key due to cert issue: $localKeyAlias", e) }
                throw IllegalStateException("ECDH Certificate chain contained non-X509 or empty certificates for alias: $localKeyAlias")
            }

            return@withContext KeyPairData(
                keyAlias = localKeyAlias,
                certificates = x509Certificates,
                keyPair = generatedKeyPair
            )
        }
}
