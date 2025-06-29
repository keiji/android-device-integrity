package dev.keiji.deviceintegrity.ui.main.playintegrity

import androidx.arch.core.executor.testing.InstantTaskExecutorRule
import dev.keiji.deviceintegrity.api.playintegrity.DeviceInfo
import dev.keiji.deviceintegrity.api.playintegrity.NonceResponse
import dev.keiji.deviceintegrity.api.playintegrity.PlayIntegrityResponseWrapper
import dev.keiji.deviceintegrity.api.playintegrity.SecurityInfo
import dev.keiji.deviceintegrity.api.playintegrity.ServerVerificationPayload
import dev.keiji.deviceintegrity.api.playintegrity.TokenPayloadExternal
import dev.keiji.deviceintegrity.provider.contract.AppInfoProvider
import dev.keiji.deviceintegrity.provider.contract.DeviceInfoProvider
import dev.keiji.deviceintegrity.provider.contract.DeviceSecurityStateProvider
import dev.keiji.deviceintegrity.repository.contract.ClassicPlayIntegrityTokenRepository
import dev.keiji.deviceintegrity.repository.contract.PlayIntegrityRepository
import dev.keiji.repository.contract.exception.ServerException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.io.IOException

@ExperimentalCoroutinesApi
class ClassicPlayIntegrityViewModelTest {

    @get:Rule
    val instantTaskExecutorRule = InstantTaskExecutorRule()

    private val testDispatcher = StandardTestDispatcher()

    private lateinit var viewModel: ClassicPlayIntegrityViewModel
    private lateinit var mockPlayIntegrityRepository: PlayIntegrityRepository
    private lateinit var mockClassicPlayIntegrityTokenRepository: ClassicPlayIntegrityTokenRepository
    private lateinit var mockDeviceInfoProvider: DeviceInfoProvider
    private lateinit var mockDeviceSecurityStateProvider: DeviceSecurityStateProvider
    private lateinit var mockAppInfoProvider: AppInfoProvider

    // Dummy data
    private val dummyDeviceInfo = DeviceInfo("brand", "model", "device", "product", "manufacturer", "hardware", "board", "bootloader", "release", 30, "fingerprint", "patch")
    private val dummySecurityInfo = SecurityInfo(true, true, true, true)
    private val dummyTokenPayloadExternal = TokenPayloadExternal(null, null, null, null, null)
    private val dummyPlayIntegrityResponseWrapper = PlayIntegrityResponseWrapper(dummyTokenPayloadExternal)
    private val dummyServerVerificationPayload = ServerVerificationPayload(dummyDeviceInfo, dummyPlayIntegrityResponseWrapper, dummySecurityInfo)


    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        mockPlayIntegrityRepository = mock()
        mockClassicPlayIntegrityTokenRepository = mock()
        mockDeviceInfoProvider = mock()
        mockDeviceSecurityStateProvider = mock()
        mockAppInfoProvider = mock()

        // Mock provider methods to return dummy data
        whenever(mockDeviceInfoProvider.BRAND).thenReturn("TestBrand")
        whenever(mockDeviceInfoProvider.MODEL).thenReturn("TestModel")
        // ... mock other DeviceInfoProvider properties as needed
        whenever(mockDeviceSecurityStateProvider.isDeviceLockEnabled).thenReturn(true)
        // ... mock other DeviceSecurityStateProvider properties
        whenever(mockAppInfoProvider.isDebugBuild).thenReturn(false)


        viewModel = ClassicPlayIntegrityViewModel(
            mockClassicPlayIntegrityTokenRepository,
            mockPlayIntegrityRepository,
            mockDeviceInfoProvider,
            mockDeviceSecurityStateProvider,
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
        val expectedResponse = NonceResponse(nonce, System.currentTimeMillis())
        whenever(mockPlayIntegrityRepository.prepareChallenge(any())).thenReturn(expectedResponse)

        viewModel.fetchNonce()
        testDispatcher.scheduler.advanceUntilIdle() // Execute coroutines

        val uiState = viewModel.uiState.first()
        assertEquals(nonce, uiState.nonce)
        assertEquals("Nonce fetched: $nonce", uiState.status)
        assertTrue(uiState.errorMessages.isEmpty())
    }

    @Test
    fun `fetchNonce serverException updates uiState with error`() = runTest {
        val serverException = ServerException(500, "Server error")
        whenever(mockPlayIntegrityRepository.prepareChallenge(any())).thenThrow(serverException)

        viewModel.fetchNonce()
        testDispatcher.scheduler.advanceUntilIdle()

        val uiState = viewModel.uiState.first()
        assertTrue(uiState.errorMessages.isNotEmpty())
        assertEquals("Server error fetching nonce.", uiState.status)
        assertEquals("Server error: 500 - Server error", uiState.errorMessages.first())
    }

    @Test
    fun `fetchNonce ioException updates uiState with error`() = runTest {
        val ioException = IOException("Network error")
        whenever(mockPlayIntegrityRepository.prepareChallenge(any())).thenThrow(ioException)

        viewModel.fetchNonce()
        testDispatcher.scheduler.advanceUntilIdle()

        val uiState = viewModel.uiState.first()
        assertTrue(uiState.errorMessages.isNotEmpty())
        assertEquals("Network error fetching nonce.", uiState.status)
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
        val sessionId = "test-session-id" // Need to ensure this is set or handled
        viewModel.fetchNonce() // This sets a session ID internally
        testDispatcher.scheduler.advanceUntilIdle() // Allow nonce (and session ID) to be set
        viewModel.updateNonce("dummy-nonce-for-token-fetch") // Ensure nonce is present for fetchIntegrityToken
        whenever(mockClassicPlayIntegrityTokenRepository.getToken(any())).thenReturn(token)
        viewModel.fetchIntegrityToken()
        testDispatcher.scheduler.advanceUntilIdle() // Ensure token is set

        whenever(mockPlayIntegrityRepository.getIntegrityVerdictClassic(any(), any(), any(), any()))
            .thenReturn(dummyServerVerificationPayload)

        viewModel.verifyToken()
        testDispatcher.scheduler.advanceUntilIdle()

        val uiState = viewModel.uiState.first()
        assertEquals("Token verification complete.", uiState.status)
        assertEquals(dummyServerVerificationPayload.playIntegrityResponse.tokenPayloadExternal, uiState.playIntegrityResponse)
        assertTrue(uiState.errorMessages.isEmpty())
    }

    @Test
    fun `verifyToken serverException updates uiState with error`() = runTest {
        val token = "test-token"
        viewModel.fetchNonce()
        testDispatcher.scheduler.advanceUntilIdle()
        viewModel.updateNonce("dummy-nonce-for-token-fetch")
        whenever(mockClassicPlayIntegrityTokenRepository.getToken(any())).thenReturn(token)
        viewModel.fetchIntegrityToken()
        testDispatcher.scheduler.advanceUntilIdle()

        val serverException = ServerException(403, "Forbidden by server")
        whenever(mockPlayIntegrityRepository.getIntegrityVerdictClassic(any(), any(), any(), any()))
            .thenThrow(serverException)

        viewModel.verifyToken()
        testDispatcher.scheduler.advanceUntilIdle()

        val uiState = viewModel.uiState.first()
        assertEquals("Server error verifying token.", uiState.status)
        assertTrue(uiState.errorMessages.isNotEmpty())
        assertEquals("Server error: 403 - Forbidden by server", uiState.errorMessages.first())
    }

    @Test
    fun `verifyToken ioException updates uiState with error`() = runTest {
        val token = "test-token"
         viewModel.fetchNonce()
        testDispatcher.scheduler.advanceUntilIdle()
        viewModel.updateNonce("dummy-nonce-for-token-fetch")
        whenever(mockClassicPlayIntegrityTokenRepository.getToken(any())).thenReturn(token)
        viewModel.fetchIntegrityToken()
        testDispatcher.scheduler.advanceUntilIdle()

        val ioException = IOException("Network connection lost")
        whenever(mockPlayIntegrityRepository.getIntegrityVerdictClassic(any(), any(), any(), any()))
            .thenThrow(ioException)

        viewModel.verifyToken()
        testDispatcher.scheduler.advanceUntilIdle()

        val uiState = viewModel.uiState.first()
        assertEquals("Network error verifying token.", uiState.status)
        assertTrue(uiState.errorMessages.isNotEmpty())
        assertEquals("Network connection lost", uiState.errorMessages.first())
    }
}
