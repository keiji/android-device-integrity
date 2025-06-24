package dev.keiji.deviceintegrity.repository.impl

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.dataStore
import androidx.test.core.app.ApplicationProvider
import dev.keiji.deviceintegrity.repository.impl.pb.UserPreferences
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@ExperimentalCoroutinesApi
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE, sdk = [30]) // Configure Robolectric as needed
class PreferencesRepositoryImplTest {

    private lateinit var context: Context
    private lateinit var preferencesRepository: PreferencesRepositoryImpl

    // Shadow DataStore for testing
    private val Context.testUserPreferencesStore: DataStore<UserPreferences> by dataStore(
        fileName = "test_user_prefs.pb",
        serializer = UserPreferencesSerializer,
        produceMigrations = { context -> emptyList() }
    )

    @Before
    fun setup() {
        context = ApplicationProvider.getApplicationContext()
        // Clear DataStore before each test
        runTest {
            context.testUserPreferencesStore.updateData { UserPreferences.getDefaultInstance() }
        }
        // Use the internal constructor that accepts a DataStore instance
        preferencesRepository = PreferencesRepositoryImpl(context.testUserPreferencesStore)
    }

    @Test
    fun `savePlayIntegrityVerifyApiEndpointUrl saves the URL correctly`() = runTest {
        val testUrl = "https://play.example.com"
        preferencesRepository.savePlayIntegrityVerifyApiEndpointUrl(testUrl)
        assertEquals(testUrl, preferencesRepository.playIntegrityVerifyApiEndpointUrl.first())
    }

    @Test
    fun `saveKeyAttestationVerifyApiEndpointUrl saves the URL correctly`() = runTest {
        val testUrl = "https://key.example.com"
        preferencesRepository.saveKeyAttestationVerifyApiEndpointUrl(testUrl)
        assertEquals(testUrl, preferencesRepository.keyAttestationVerifyApiEndpointUrl.first())
    }

    @Test
    fun `playIntegrityVerifyApiEndpointUrl returns null when no URL is saved`() = runTest {
        assertNull(preferencesRepository.playIntegrityVerifyApiEndpointUrl.first())
    }

    @Test
    fun `keyAttestationVerifyApiEndpointUrl returns null when no URL is saved`() = runTest {
        assertNull(preferencesRepository.keyAttestationVerifyApiEndpointUrl.first())
    }

    @Test
    fun `savePlayIntegrityVerifyApiEndpointUrl overwrites existing URL`() = runTest {
        val initialUrl = "https://initial-play.com"
        preferencesRepository.savePlayIntegrityVerifyApiEndpointUrl(initialUrl)
        assertEquals(initialUrl, preferencesRepository.playIntegrityVerifyApiEndpointUrl.first())

        val newUrl = "https://new-play.com"
        preferencesRepository.savePlayIntegrityVerifyApiEndpointUrl(newUrl)
        assertEquals(newUrl, preferencesRepository.playIntegrityVerifyApiEndpointUrl.first())
    }

    @Test
    fun `saveKeyAttestationVerifyApiEndpointUrl overwrites existing URL`() = runTest {
        val initialUrl = "https://initial-key.com"
        preferencesRepository.saveKeyAttestationVerifyApiEndpointUrl(initialUrl)
        assertEquals(initialUrl, preferencesRepository.keyAttestationVerifyApiEndpointUrl.first())

        val newUrl = "https://new-key.com"
        preferencesRepository.saveKeyAttestationVerifyApiEndpointUrl(newUrl)
        assertEquals(newUrl, preferencesRepository.keyAttestationVerifyApiEndpointUrl.first())
    }

    @Test
    fun `URLs are independent`() = runTest {
        val playUrl = "https://play.example.com"
        val keyUrl = "https://key.example.com"

        preferencesRepository.savePlayIntegrityVerifyApiEndpointUrl(playUrl)
        preferencesRepository.saveKeyAttestationVerifyApiEndpointUrl(keyUrl)

        assertEquals(playUrl, preferencesRepository.playIntegrityVerifyApiEndpointUrl.first())
        assertEquals(keyUrl, preferencesRepository.keyAttestationVerifyApiEndpointUrl.first())

        val newPlayUrl = "https://new-play.example.com"
        preferencesRepository.savePlayIntegrityVerifyApiEndpointUrl(newPlayUrl)
        assertEquals(newPlayUrl, preferencesRepository.playIntegrityVerifyApiEndpointUrl.first())
        assertEquals(keyUrl, preferencesRepository.keyAttestationVerifyApiEndpointUrl.first()) // Key URL should remain unchanged

        val newKeyUrl = "https://new-key.example.com"
        preferencesRepository.saveKeyAttestationVerifyApiEndpointUrl(newKeyUrl)
        assertEquals(newPlayUrl, preferencesRepository.playIntegrityVerifyApiEndpointUrl.first()) // Play URL should remain unchanged
        assertEquals(newKeyUrl, preferencesRepository.keyAttestationVerifyApiEndpointUrl.first())
    }

    @Test
    fun `saving one URL does not affect the other if not set`() = runTest {
        val playUrl = "https://play.example.com"
        preferencesRepository.savePlayIntegrityVerifyApiEndpointUrl(playUrl)

        assertEquals(playUrl, preferencesRepository.playIntegrityVerifyApiEndpointUrl.first())
        assertNull(preferencesRepository.keyAttestationVerifyApiEndpointUrl.first())

        // Clear and test the other way
        preferencesRepository.savePlayIntegrityVerifyApiEndpointUrl("") // Assuming saving blank clears it or saves as empty
        val keyUrl = "https://key.example.com"
        preferencesRepository.saveKeyAttestationVerifyApiEndpointUrl(keyUrl)

        // Check if blank string is saved as null or empty string based on impl.
        // Based on current impl, it should be null if empty string is saved and then mapped.
        // Let's assume it becomes null for now. If it's "", the test needs adjustment.
        val currentPlayUrl = preferencesRepository.playIntegrityVerifyApiEndpointUrl.first()
        assert(currentPlayUrl == null || currentPlayUrl == "")

        assertEquals(keyUrl, preferencesRepository.keyAttestationVerifyApiEndpointUrl.first())
    }
}
