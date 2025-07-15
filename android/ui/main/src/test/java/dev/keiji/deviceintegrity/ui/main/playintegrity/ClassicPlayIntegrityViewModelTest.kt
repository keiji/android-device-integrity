package dev.keiji.deviceintegrity.ui.main.playintegrity

import dev.keiji.deviceintegrity.api.DeviceInfo
import dev.keiji.deviceintegrity.api.playintegrity.NonceResponseV2
import dev.keiji.deviceintegrity.api.playintegrity.PlayIntegrityResponseWrapper
import dev.keiji.deviceintegrity.api.SecurityInfo
import dev.keiji.deviceintegrity.api.playintegrity.ServerVerificationPayload
import dev.keiji.deviceintegrity.api.playintegrity.TokenPayloadExternal
import dev.keiji.deviceintegrity.provider.contract.AppInfoProvider
import dev.keiji.deviceintegrity.provider.contract.DeviceInfoProvider
import dev.keiji.deviceintegrity.provider.contract.DeviceSecurityStateProvider
import dev.keiji.deviceintegrity.provider.contract.GooglePlayDeveloperServiceInfo
import dev.keiji.deviceintegrity.provider.contract.GooglePlayDeveloperServiceInfoProvider
import dev.keiji.deviceintegrity.repository.contract.ClassicPlayIntegrityTokenRepository
import dev.keiji.deviceintegrity.repository.contract.PlayIntegrityRepository
import dev.keiji.deviceintegrity.repository.contract.exception.ServerException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.kotlin.any
import org.mockito.kotlin.eq
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.IOException

@Config(application = dagger.hilt.android.testing.HiltTestApplication::class)
@RunWith(RobolectricTestRunner::class)
@ExperimentalCoroutinesApi
class ClassicPlayIntegrityViewModelTest {

    private val testDispatcher = StandardTestDispatcher()

    private lateinit var viewModel: ClassicPlayIntegrityViewModel
    private lateinit var mockPlayIntegrityRepository: PlayIntegrityRepository
    private lateinit var mockClassicPlayIntegrityTokenRepository: ClassicPlayIntegrityTokenRepository
    private lateinit var mockDeviceInfoProvider: DeviceInfoProvider
    private lateinit var mockDeviceSecurityStateProvider: DeviceSecurityStateProvider
    private lateinit var mockGooglePlayDeveloperServiceInfoProvider: GooglePlayDeveloperServiceInfoProvider
    private lateinit var mockAppInfoProvider: AppInfoProvider

    // Dummy data
    private val dummyDeviceInfo = DeviceInfo("brand", "model", "device", "product", "manufacturer", "hardware", "board", "bootloader", "release", 30, "fingerprint", "patch")
    private val dummySecurityInfo = SecurityInfo(true, true, true, true)
    private val dummyGooglePlayDeveloperServiceInfo = GooglePlayDeveloperServiceInfo(123L, "1.2.3")
    private val dummyTokenPayloadExternal = TokenPayloadExternal(null, null, null, null, null)
    private val dummyPlayIntegrityResponseWrapper = PlayIntegrityResponseWrapper(dummyTokenPayloadExternal)
    private val dummyServerVerificationPayload = ServerVerificationPayload(
        deviceInfo = dummyDeviceInfo,
        playIntegrityResponse = dummyPlayIntegrityResponseWrapper,
        securityInfo = dummySecurityInfo,
        googlePlayDeveloperServiceInfo = dummyGooglePlayDeveloperServiceInfo
    )


    @Before
    fun setUp() = runTest {
        Dispatchers.setMain(testDispatcher)
        mockPlayIntegrityRepository = mock()
        mockClassicPlayIntegrityTokenRepository = mock()
        mockDeviceInfoProvider = mock()
        mockDeviceSecurityStateProvider = mock()
        mockGooglePlayDeveloperServiceInfoProvider = mock()
        mockAppInfoProvider = mock()

        // Mock provider methods to return dummy data
        whenever(mockGooglePlayDeveloperServiceInfoProvider.provide()).thenReturn(dummyGooglePlayDeveloperServiceInfo)
        whenever(mockDeviceInfoProvider.BRAND).thenReturn("TestBrand")
        whenever(mockDeviceInfoProvider.MODEL).thenReturn("TestModel")
        whenever(mockDeviceInfoProvider.DEVICE).thenReturn("TestDevice")
        whenever(mockDeviceInfoProvider.PRODUCT).thenReturn("TestDevice")
        whenever(mockDeviceInfoProvider.BOARD).thenReturn("TestDevice")
        whenever(mockDeviceInfoProvider.BASE_OS).thenReturn("TestDevice")
        whenever(mockDeviceInfoProvider.BOOTLOADER).thenReturn("TestDevice")
        whenever(mockDeviceInfoProvider.DISPLAY).thenReturn("TestDevice")
        whenever(mockDeviceInfoProvider.FINGERPRINT).thenReturn("TestDevice")
        whenever(mockDeviceInfoProvider.HARDWARE).thenReturn("TestDevice")
        whenever(mockDeviceInfoProvider.HOST).thenReturn("TestDevice")
        whenever(mockDeviceInfoProvider.ID).thenReturn("TestDevice")
        whenever(mockDeviceInfoProvider.MANUFACTURER).thenReturn("TestDevice")
        whenever(mockDeviceInfoProvider.SDK_INT).thenReturn(30)
        whenever(mockDeviceInfoProvider.SECURITY_PATCH).thenReturn("TestDevice")
        whenever(mockDeviceInfoProvider.TAGS).thenReturn("TestDevice")
        whenever(mockDeviceInfoProvider.TIME).thenReturn(0)
        whenever(mockDeviceInfoProvider.TYPE).thenReturn("TestDevice")
        whenever(mockDeviceInfoProvider.USER).thenReturn("TestDevice")
        whenever(mockDeviceInfoProvider.VERSION_RELEASE).thenReturn("TestDevice")
        whenever(mockDeviceInfoProvider.VERSION_INCREMENTAL).thenReturn("TestDevice")

        // ... mock other DeviceInfoProvider properties as needed
        whenever(mockDeviceSecurityStateProvider.isDeviceLockEnabled).thenReturn(true)
        // ... mock other DeviceSecurityStateProvider properties
        whenever(mockAppInfoProvider.isDebugBuild).thenReturn(false)


        viewModel = ClassicPlayIntegrityViewModel(
            mockClassicPlayIntegrityTokenRepository,
            mockPlayIntegrityRepository,
            mockDeviceInfoProvider,
            mockDeviceSecurityStateProvider,
            mockGooglePlayDeveloperServiceInfoProvider,
            mockAppInfoProvider
        )
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `fetchNonce success updates uiState with nonce`() = runTest {
        val nonce = "test-nonce"
        val sessionId = "test-session-id"
        val expectedResponse = NonceResponseV2(sessionId, nonce)
        whenever(mockPlayIntegrityRepository.getNonceV2()).thenReturn(expectedResponse)

        viewModel.fetchNonce()
        testDispatcher.scheduler.advanceUntilIdle() // Execute coroutines

        val uiState = viewModel.uiState.first()
        assertEquals(nonce, uiState.nonce)
        assertEquals("Nonce fetched: $nonce", uiState.status)
        assertEquals(sessionId, uiState.currentSessionId)
        assertTrue(uiState.errorMessages.isEmpty())
    }

    @Test
    fun `fetchNonce serverException updates uiState with error`() = runTest {
        val serverException = ServerException(500, "Server error")
        whenever(mockPlayIntegrityRepository.getNonceV2()).thenThrow(serverException)

        viewModel.fetchNonce()
        advanceUntilIdle()

        val uiState = viewModel.uiState.first()
        assertTrue(uiState.errorMessages.isNotEmpty())
        assertEquals("Server error fetching nonce: Server error", uiState.status) // Updated
        assertEquals("Server error: 500 - Server error", uiState.errorMessages.first())
    }

    @Test
    fun `fetchNonce ioException updates uiState with error`() = runTest {
        val ioException = IOException("Network error")
        whenever(mockPlayIntegrityRepository.getNonceV2()).thenThrow(ioException)

        viewModel.fetchNonce()
        advanceUntilIdle()

        val uiState = viewModel.uiState.first()
        assertTrue(uiState.errorMessages.isNotEmpty())
        assertEquals("Network error fetching nonce: Network error", uiState.status) // Updated
        assertEquals("Network error", uiState.errorMessages.first())
    }

    @Test
    fun `fetchIntegrityToken success updates uiState with token`() = runTest {
        val nonce = "test-nonce"
        val token = "test-token"
        viewModel.updateNonce(nonce) // Set nonce first
        whenever(mockClassicPlayIntegrityTokenRepository.getToken(nonce)).thenReturn(token)

        viewModel.fetchIntegrityToken()
        testDispatcher.scheduler.advanceUntilIdle()

        val uiState = viewModel.uiState.first()
        assertEquals(token, uiState.integrityToken)
        assertEquals("Token fetched successfully (see Logcat for token)", uiState.status)
    }

    @Test
    fun `verifyToken success updates uiState with response`() = runTest {
        val token = "test-token"
        val nonce = "test-nonce"
        val sessionId = "test-session-id"
        val expectedNonceResponse = NonceResponseV2(sessionId, nonce)
        whenever(mockPlayIntegrityRepository.getNonceV2()).thenReturn(expectedNonceResponse)

        viewModel.fetchNonce()
        testDispatcher.scheduler.advanceUntilIdle()

        val fetchedUiState = viewModel.uiState.first()
        val currentSessionId = fetchedUiState.currentSessionId
        assertEquals(sessionId, currentSessionId)

        whenever(mockClassicPlayIntegrityTokenRepository.getToken(any())).thenReturn(token)
        viewModel.fetchIntegrityToken()
        testDispatcher.scheduler.advanceUntilIdle()

        whenever(mockPlayIntegrityRepository.verifyTokenClassic(any(), eq(currentSessionId!!), any(), any(), any()))
            .thenReturn(dummyServerVerificationPayload)

        viewModel.verifyToken()
        testDispatcher.scheduler.advanceUntilIdle()

        val uiState = viewModel.uiState.first()
        assertEquals("Token verification complete.", uiState.status)
        assertEquals(dummyServerVerificationPayload, uiState.serverVerificationPayload)
        assertTrue(uiState.errorMessages.isEmpty())
    }

    @Test
    fun `verifyToken serverException updates uiState with error`() = runTest {
        val token = "test-token"
        val nonce = "test-nonce"
        val sessionId = "test-session-id"
        val expectedNonceResponse = NonceResponseV2(sessionId, nonce)
        whenever(mockPlayIntegrityRepository.getNonceV2()).thenReturn(expectedNonceResponse)

        viewModel.fetchNonce()
        testDispatcher.scheduler.advanceUntilIdle()

        val fetchedUiState = viewModel.uiState.first()
        val currentSessionId = fetchedUiState.currentSessionId
        assertEquals(sessionId, currentSessionId)

        whenever(mockClassicPlayIntegrityTokenRepository.getToken(any())).thenReturn(token)
        viewModel.fetchIntegrityToken()
        testDispatcher.scheduler.advanceUntilIdle()

        val serverException = ServerException(403, "Forbidden by server")
        whenever(mockPlayIntegrityRepository.verifyTokenClassic(any(), eq(currentSessionId!!), any(), any(), any()))
            .thenThrow(serverException)

        viewModel.verifyToken()
        testDispatcher.scheduler.advanceUntilIdle()

        val uiState = viewModel.uiState.first()
        assertEquals("Server error verifying token: Forbidden by server", uiState.status) // Updated
        assertTrue(uiState.errorMessages.isNotEmpty())
        assertEquals("Server error: 403 - Forbidden by server", uiState.errorMessages.first())
    }

    @Test
    fun `verifyToken ioException updates uiState with error`() = runTest {
        val token = "test-token"
        val nonce = "test-nonce"
        val sessionId = "test-session-id"
        val expectedNonceResponse = NonceResponseV2(sessionId, nonce)
        whenever(mockPlayIntegrityRepository.getNonceV2()).thenReturn(expectedNonceResponse)

        viewModel.fetchNonce()
        testDispatcher.scheduler.advanceUntilIdle()

        val fetchedUiState = viewModel.uiState.first()
        val currentSessionId = fetchedUiState.currentSessionId
        assertEquals(sessionId, currentSessionId)

        whenever(mockClassicPlayIntegrityTokenRepository.getToken(any())).thenReturn(token)
        viewModel.fetchIntegrityToken()
        testDispatcher.scheduler.advanceUntilIdle()

        val ioException = IOException("Network connection lost")
        whenever(mockPlayIntegrityRepository.verifyTokenClassic(any(), eq(currentSessionId!!), any(), any(), any()))
            .thenThrow(ioException)

        viewModel.verifyToken()
        testDispatcher.scheduler.advanceUntilIdle()

        val uiState = viewModel.uiState.first()
        assertEquals("Network error verifying token: Network connection lost", uiState.status) // Updated
        assertTrue(uiState.errorMessages.isNotEmpty())
        assertEquals("Network connection lost", uiState.errorMessages.first())
    }

    @Test
    fun `init loads GooglePlayDeveloperServiceInfo and updates uiState`() = runTest {
        // ViewModel is initialized in setUp, which should trigger the init block.
        testDispatcher.scheduler.advanceUntilIdle() // Ensure coroutines in init complete

        val uiState = viewModel.uiState.first()
        assertEquals(dummyGooglePlayDeveloperServiceInfo, uiState.googlePlayDeveloperServiceInfo)
    }

    @Test
    fun `verifyToken uses GooglePlayDeveloperServiceInfo from uiState`() = runTest {
        val token = "test-token"
        val nonce = "test-nonce"
        val sessionId = "test-session-id"
        val expectedNonceResponse = NonceResponseV2(sessionId, nonce)
        whenever(mockPlayIntegrityRepository.getNonceV2()).thenReturn(expectedNonceResponse)

        viewModel.fetchNonce()
        testDispatcher.scheduler.advanceUntilIdle()

        val fetchedUiState = viewModel.uiState.first()
        val currentSessionId = fetchedUiState.currentSessionId
        assertEquals(sessionId, currentSessionId)

        whenever(mockClassicPlayIntegrityTokenRepository.getToken(any())).thenReturn(token)
        viewModel.fetchIntegrityToken()
        testDispatcher.scheduler.advanceUntilIdle()

        whenever(mockPlayIntegrityRepository.verifyTokenClassic(
            eq(token),
            eq(currentSessionId!!), // sessionId
            any(), // deviceInfo
            any(), // securityInfo
            eq(dummyGooglePlayDeveloperServiceInfo) // Explicitly check this arg
        )).thenReturn(dummyServerVerificationPayload)

        viewModel.verifyToken()
        testDispatcher.scheduler.advanceUntilIdle()

        val finalUiState = viewModel.uiState.first()
        assertEquals("Token verification complete.", finalUiState.status)
        assertEquals(dummyServerVerificationPayload.playIntegrityResponse, finalUiState.serverVerificationPayload?.playIntegrityResponse)
    }
}
