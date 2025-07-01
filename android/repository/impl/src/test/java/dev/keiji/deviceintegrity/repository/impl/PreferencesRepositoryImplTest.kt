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
}
