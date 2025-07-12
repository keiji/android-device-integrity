package dev.keiji.deviceintegrity.repository.impl

import android.content.Context
import android.os.Build
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.keiji.deviceintegrity.provider.contract.DeviceSecurityStateProvider
import dev.keiji.deviceintegrity.provider.impl.DeviceSecurityStateProviderImpl
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestCoroutineScheduler
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import java.security.interfaces.ECPublicKey

@ExperimentalCoroutinesApi
@RunWith(AndroidJUnit4::class)
class KeyPairRepositoryImplStrongBoxTest {

    private lateinit var context: Context
    private lateinit var keyStore: KeyStore
    private lateinit var keyPairRepository: KeyPairRepositoryImpl
    private lateinit var deviceSecurityStateProvider: DeviceSecurityStateProvider

    private val testScheduler = TestCoroutineScheduler()
    private val testDispatcher = StandardTestDispatcher(testScheduler)

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext<Context>()
        keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        deviceSecurityStateProvider = DeviceSecurityStateProviderImpl(context)
        keyPairRepository = KeyPairRepositoryImpl(testDispatcher, deviceSecurityStateProvider)

        cleanupTestKeys()
    }

    @After
    fun tearDown() {
        cleanupTestKeys()
    }

    private fun cleanupTestKeys() {
        keyStore.aliases().toList().forEach { alias ->
            if (alias.startsWith("strongbox_test_")) {
                try {
                    keyStore.deleteEntry(alias)
                } catch (e: Exception) {
                    // Ignore
                }
            }
        }
    }

    @Test
    fun generateEcKeyPair_withStrongBox_successfullyGeneratesKey() = runTest(testScheduler) {
        assumeTrue(
            "Device does not support StrongBox, skipping test.",
            deviceSecurityStateProvider.hasStrongBox
        )

        val challenge = "ec_strongbox_challenge".toByteArray()
        val result = keyPairRepository.generateEcKeyPair(challenge, true)

        assertNotNull(result)
        assertTrue(keyStore.containsAlias(result.keyAlias))

        val publicKey = result.keyPair.public as ECPublicKey
        assertNotNull(publicKey)

        keyStore.deleteEntry(result.keyAlias)
    }

    @Test
    fun generateRsaKeyPair_withStrongBox_successfullyGeneratesKey() = runTest(testScheduler) {
        assumeTrue(
            "Device does not support StrongBox, skipping test.",
            deviceSecurityStateProvider.hasStrongBox
        )

        val challenge = "rsa_strongbox_challenge".toByteArray()
        val result = keyPairRepository.generateRsaKeyPair(challenge, true)

        assertNotNull(result)
        assertTrue(keyStore.containsAlias(result.keyAlias))

        val publicKey = result.keyPair.public as java.security.interfaces.RSAPublicKey
        assertNotNull(publicKey)

        keyStore.deleteEntry(result.keyAlias)
    }

    @Test
    fun generateEcdhKeyPair_withStrongBox_successfullyGeneratesKey() = runTest(testScheduler) {
        assumeTrue(
            "Device does not support StrongBox, skipping test.",
            deviceSecurityStateProvider.hasStrongBox
        )
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return@runTest
        }

        val challenge = "ecdh_strongbox_challenge".toByteArray()
        val result = keyPairRepository.generateEcdhKeyPair(challenge, true)

        assertNotNull(result)
        assertTrue(keyStore.containsAlias(result.keyAlias))

        val publicKey = result.keyPair.public as ECPublicKey
        assertNotNull(publicKey)

        keyStore.deleteEntry(result.keyAlias)
    }
}
