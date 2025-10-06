package dev.keiji.deviceintegrity.repository.impl

import dagger.hilt.android.testing.HiltAndroidTest
import dev.keiji.deviceintegrity.api.DeviceInfo
import dev.keiji.deviceintegrity.api.playintegrity.NonceResponse
import dev.keiji.deviceintegrity.api.playintegrity.PlayIntegrityResponseWrapper
import dev.keiji.deviceintegrity.api.playintegrity.PlayIntegrityTokenVerifyApiClient
import dev.keiji.deviceintegrity.api.SecurityInfo
import dev.keiji.deviceintegrity.api.playintegrity.ServerVerificationPayload
import dev.keiji.deviceintegrity.api.playintegrity.TokenPayloadExternal
import dev.keiji.deviceintegrity.provider.contract.GooglePlayDeveloperServiceInfo
import dev.keiji.deviceintegrity.repository.contract.exception.ServerException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import retrofit2.HttpException
import retrofit2.Response
import java.io.IOException
import kotlin.test.assertFailsWith

@HiltAndroidTest
@Config(application = dagger.hilt.android.testing.HiltTestApplication::class)
@RunWith(RobolectricTestRunner::class) // To enable Android framework classes if Hilt needs them for context etc.
@ExperimentalCoroutinesApi
class PlayIntegrityRepositoryImplTest {

    private val testDispatcher = StandardTestDispatcher()

    private lateinit var mockPlayIntegrityTokenVerifyApiClient: PlayIntegrityTokenVerifyApiClient
    private lateinit var repository: PlayIntegrityRepositoryImpl

    // Dummy data for tests
    private val dummyDeviceInfo = DeviceInfo(
        "brand",
        "model",
        "device",
        "product",
        "manufacturer",
        "hardware",
        "board",
        "bootloader",
        "release",
        30,
        "fingerprint",
        "patch"
    )
    private val dummySecurityInfo = SecurityInfo(true, true, true, true)
    private val dummyGooglePlayDeveloperServiceInfo = GooglePlayDeveloperServiceInfo(256L, "dummyVersion")
    private val dummyTokenPayloadExternal = TokenPayloadExternal(null, null, null, null, null)
    private val dummyPlayIntegrityResponseWrapper =
        PlayIntegrityResponseWrapper(dummyTokenPayloadExternal)


    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)

        mockPlayIntegrityTokenVerifyApiClient = mock()
        repository = PlayIntegrityRepositoryImpl(mockPlayIntegrityTokenVerifyApiClient)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    // --- verifyTokenStandard Tests ---

    @Test
    fun `verifyTokenStandard_success_should_return_ServerVerificationPayload`() = runTest {
        val expectedResponse = ServerVerificationPayload(
            dummyDeviceInfo,
            dummyPlayIntegrityResponseWrapper,
            dummySecurityInfo
        )
        whenever(mockPlayIntegrityTokenVerifyApiClient.verifyTokenStandard(any())).thenReturn(
            expectedResponse
        )

        val result = repository.verifyTokenStandard(
            "token",
            "sid",
            "binding",
            dummyDeviceInfo,
            dummySecurityInfo,
            dummyGooglePlayDeveloperServiceInfo
        )
        Assert.assertEquals(expectedResponse, result)
    }

    @Test
    fun `verifyTokenStandard_httpException_should_throw_ServerException`() = runTest {
        val httpException = HttpException(
            Response.error<ServerVerificationPayload>(
                400,
                "Error".toResponseBody("text/plain".toMediaTypeOrNull())
            )
        )
        whenever(mockPlayIntegrityTokenVerifyApiClient.verifyTokenStandard(any())).thenThrow(
            httpException
        )

        val exception = assertFailsWith<ServerException> {
            repository.verifyTokenStandard(
                "token",
                "sid",
                "binding",
                dummyDeviceInfo,
                dummySecurityInfo,
                dummyGooglePlayDeveloperServiceInfo
            )
        }
        Assert.assertEquals(400, exception.errorCode)
        Assert.assertEquals("Error", exception.errorMessage)
    }

    @Test
    fun verifyTokenStandard_ioException_should_throw_IOException() = runTest {
        val ioException = IOException("Network error")
        whenever(mockPlayIntegrityTokenVerifyApiClient.verifyTokenStandard(any())).thenAnswer { throw ioException }

        assertFailsWith<IOException> {
            repository.verifyTokenStandard(
                "token",
                "sid",
                "binding",
                dummyDeviceInfo,
                dummySecurityInfo,
                dummyGooglePlayDeveloperServiceInfo
            )
        }
        testDispatcher.scheduler.advanceUntilIdle()
    }

    // --- verifyTokenClassic Tests ---
    @Test
    fun `verifyTokenClassic_success_should_return_ServerVerificationPayload`() = runTest {
        val expectedResponse = ServerVerificationPayload(
            dummyDeviceInfo,
            dummyPlayIntegrityResponseWrapper,
            dummySecurityInfo
        )
        whenever(mockPlayIntegrityTokenVerifyApiClient.verifyTokenClassic(any())).thenReturn(
            expectedResponse
        )

        val result =
            repository.verifyTokenClassic(
                "token",
                "sid",
                dummyDeviceInfo,
                dummySecurityInfo,
                dummyGooglePlayDeveloperServiceInfo
            )
        Assert.assertEquals(expectedResponse, result)
    }

    @Test
    fun `verifyTokenClassic_httpException_should_throw_ServerException`() = runTest {
        val httpException = HttpException(
            Response.error<ServerVerificationPayload>(
                403,
                "Forbidden".toResponseBody("text/plain".toMediaTypeOrNull())
            )
        )
        whenever(mockPlayIntegrityTokenVerifyApiClient.verifyTokenClassic(any())).thenThrow(
            httpException
        )

        val exception = assertFailsWith<ServerException> {
            repository.verifyTokenClassic(
                "token",
                "sid",
                dummyDeviceInfo,
                dummySecurityInfo,
                dummyGooglePlayDeveloperServiceInfo
            )
        }
        Assert.assertEquals(403, exception.errorCode)
        Assert.assertEquals("Forbidden", exception.errorMessage)
    }

}
