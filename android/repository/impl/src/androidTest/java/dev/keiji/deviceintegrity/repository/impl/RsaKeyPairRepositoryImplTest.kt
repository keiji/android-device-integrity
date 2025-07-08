package dev.keiji.deviceintegrity.repository.impl

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestCoroutineScheduler
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyPairGenerator
import java.security.KeyStore

@ExperimentalCoroutinesApi
@RunWith(AndroidJUnit4::class)
class RsaKeyPairRepositoryImplTest {

    private lateinit var context: Context
    private lateinit var keyStore: KeyStore
    private lateinit var rsaKeyPairRepository: RsaKeyPairRepositoryImpl

    private val testScheduler = TestCoroutineScheduler()
    private val testDispatcher = StandardTestDispatcher(testScheduler)

    private val testAliasBase = "instrumentationTestAliasRsa"

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext<Context>()
        keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        rsaKeyPairRepository = RsaKeyPairRepositoryImpl(testDispatcher, context)

        cleanupTestKeys()
    }

    @After
    fun tearDown() {
        cleanupTestKeys()
    }

    private fun cleanupTestKeys() {
        keyStore.aliases().toList().forEach { alias ->
            if (alias.startsWith(testAliasBase) || alias.length == 36) { // UUID length
                try {
                    keyStore.deleteEntry(alias)
                } catch (e: Exception) {
                    // Ignore
                }
            }
        }
    }

    private fun generateTestKey(alias: String): java.security.KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
        keyPairGenerator.initialize(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setKeySize(2048)
                .build()
        )
        return keyPairGenerator.generateKeyPair()
    }

    @Test
    fun getKeyPair_returnsKeyPair_whenAliasExists() = runTest(testScheduler) {
        val alias = "${testAliasBase}GetKey"
        val expectedKeyPair = generateTestKey(alias)

        val result = rsaKeyPairRepository.getKeyPair(alias)

        assertNotNull(result)
        assertEquals(
            expectedKeyPair.public.encoded.toHexString(),
            result?.public?.encoded?.toHexString()
        )
    }

    @Test
    fun getKeyPair_returnsNull_whenAliasDoesNotExist() = runTest(testScheduler) {
        val result = rsaKeyPairRepository.getKeyPair("nonExistentAliasForGetKeyRsa")
        assertNull(result)
    }

    @Test
    fun removeKeyPair_deletesExistingKey() = runTest(testScheduler) {
        val alias = "${testAliasBase}RemoveKey"
        generateTestKey(alias)
        assertTrue(keyStore.containsAlias(alias))

        rsaKeyPairRepository.removeKeyPair(alias)

        assertFalse(keyStore.containsAlias(alias))
    }

    @Test
    fun removeKeyPair_doesNothing_whenAliasDoesNotExist() = runTest(testScheduler) {
        val alias = "nonExistentAliasForRemoveRsa"
        assertFalse(keyStore.containsAlias(alias))

        rsaKeyPairRepository.removeKeyPair(alias) // Should not throw

        assertFalse(keyStore.containsAlias(alias))
    }

    @Test
    fun generateKeyPair_successfullyGeneratesKey_andReturnsKeyPairDataWithCertificates() = runTest(testScheduler) {
        val challenge = "test_challenge_instrumentation_rsa".toByteArray()

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            println("Skipping generateKeyPair_successfullyGeneratesKey test on pre-N SDK (${Build.VERSION.SDK_INT}) as it requires challenge.")
            return@runTest
        }

        val result = rsaKeyPairRepository.generateKeyPair(challenge)

        assertNotNull(result)
        assertTrue(result.keyAlias.isNotEmpty())
        assertNotNull(result.certificates)
        assertTrue(result.certificates.isNotEmpty())
        assertTrue(keyStore.containsAlias(result.keyAlias))
        assertEquals(result.certificates[0].publicKey.encoded.toHexString(), keyStore.getCertificate(result.keyAlias).publicKey.encoded.toHexString())

        if (keyStore.containsAlias(result.keyAlias)) {
            keyStore.deleteEntry(result.keyAlias)
        }
    }

    @Test
    fun generateKeyPair_throwsUnsupportedOperationException_onPreNSDK_whenChallengeProvided() = runTest(testScheduler) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            println("Skipping generateKeyPair_throwsUnsupportedOperationException_onPreNSDK test on N+ SDK (${Build.VERSION.SDK_INT}).")
            return@runTest
        }

        val challenge = "test_challenge_pre_N_rsa".toByteArray()
        var exceptionThrown = false
        try {
            rsaKeyPairRepository.generateKeyPair(challenge)
        } catch (e: UnsupportedOperationException) {
            exceptionThrown = true
            assertTrue(e.message?.contains("not supported before Android N") == true)
        }
        assertTrue("UnsupportedOperationException was expected but not thrown on SDK ${Build.VERSION.SDK_INT}.",exceptionThrown)
    }

    @Test
    fun generateKeyPair_throwsIllegalArgumentException_onNPlusSDK_whenChallengeIsEmpty() = runTest(testScheduler) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            println("Skipping generateKeyPair_throwsIllegalArgumentException_onNPlusSDK test on pre-N SDK (${Build.VERSION.SDK_INT}).")
            return@runTest
        }

        val emptyChallenge = byteArrayOf()
        var exceptionThrown = false
        try {
            rsaKeyPairRepository.generateKeyPair(emptyChallenge)
        } catch (e: IllegalArgumentException) {
            exceptionThrown = true
            assertTrue(e.message?.contains("Challenge cannot be empty") == true)
        }
        assertTrue("IllegalArgumentException was expected but not thrown on SDK ${Build.VERSION.SDK_INT}.",exceptionThrown)
    }

    // Helper to convert ByteArray to HexString for easier comparison of public keys
    private fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }
}
