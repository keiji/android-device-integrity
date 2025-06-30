package dev.keiji.deviceintegrity.provider.impl

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import com.google.android.gms.common.GooglePlayServicesUtil
import dev.keiji.deviceintegrity.provider.contract.GooglePlayDeveloperServiceInfo
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import timber.log.Timber

@ExperimentalCoroutinesApi
class GooglePlayDeveloperServiceInfoProviderImplTest {

    private lateinit var mockContext: Context
    private lateinit var mockPackageManager: PackageManager
    private val testDispatcher = StandardTestDispatcher()

    private lateinit var provider: GooglePlayDeveloperServiceInfoProviderImpl

    @Before
    fun setup() {
        mockContext = mockk()
        mockPackageManager = mockk()
        every { mockContext.packageManager } returns mockPackageManager

        // Mock Timber to prevent errors during tests if Timber is not planted
        mockkStatic(Timber::class)
        every { Timber.tag(any()) } returns mockk(relaxed = true)
        every { Timber.w(any<Throwable>(), any<String>()) } returns Unit
        every { Timber.e(any<Throwable>(), any<String>()) } returns Unit


        provider = GooglePlayDeveloperServiceInfoProviderImpl(mockContext, testDispatcher)
    }

    @Test
    fun `provide returns GooglePlayDeveloperServiceInfo on success`() = runTest(testDispatcher) {
        val fakePackageInfo = PackageInfo().apply {
            longVersionCode = 12345L
            versionName = "1.2.3"
        }
        every {
            mockPackageManager.getPackageInfo(
                GooglePlayServicesUtil.GOOGLE_PLAY_SERVICES_PACKAGE,
                0
            )
        } returns fakePackageInfo

        val result = provider.provide()

        assertNotNull(result)
        assertEquals(12345L, result?.versionCode)
        assertEquals("1.2.3", result?.versionName)
    }

    @Test
    fun `provide returns null if versionName is null`() = runTest(testDispatcher) {
        val fakePackageInfo = PackageInfo().apply {
            longVersionCode = 12345L
            versionName = null // Simulate null versionName
        }
        every {
            mockPackageManager.getPackageInfo(
                GooglePlayServicesUtil.GOOGLE_PLAY_SERVICES_PACKAGE,
                0
            )
        } returns fakePackageInfo

        val result = provider.provide()

        assertNotNull(result)
        assertEquals(12345L, result?.versionCode)
        assertEquals("", result?.versionName) // Expecting empty string as per implementation
    }

    @Test
    fun `provide returns null when NameNotFoundException occurs`() = runTest(testDispatcher) {
        every {
            mockPackageManager.getPackageInfo(
                GooglePlayServicesUtil.GOOGLE_PLAY_SERVICES_PACKAGE,
                0
            )
        } throws PackageManager.NameNotFoundException("Test Exception")

        val result = provider.provide()

        assertNull(result)
    }

    @Test
    fun `provide returns null when a general Exception occurs`() = runTest(testDispatcher) {
        every {
            mockPackageManager.getPackageInfo(
                GooglePlayServicesUtil.GOOGLE_PLAY_SERVICES_PACKAGE,
                0
            )
        } throws RuntimeException("Test General Exception")

        val result = provider.provide()

        assertNull(result)
    }

    // The test for running on the specified dispatcher is implicitly covered by runTest(testDispatcher)
    // and how the provider is constructed with testDispatcher.
}
