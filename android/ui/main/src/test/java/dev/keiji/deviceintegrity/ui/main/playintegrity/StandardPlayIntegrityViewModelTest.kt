package dev.keiji.deviceintegrity.ui.main.playintegrity

import dev.keiji.deviceintegrity.api.playintegrity.DeviceInfo
import dev.keiji.deviceintegrity.api.playintegrity.PlayIntegrityResponseWrapper
import dev.keiji.deviceintegrity.api.playintegrity.SecurityInfo
import dev.keiji.deviceintegrity.api.playintegrity.ServerVerificationPayload
import dev.keiji.deviceintegrity.api.playintegrity.TokenPayloadExternal
import dev.keiji.deviceintegrity.provider.contract.AppInfoProvider
import dev.keiji.deviceintegrity.provider.contract.DeviceInfoProvider
import dev.keiji.deviceintegrity.provider.contract.DeviceSecurityStateProvider
import dev.keiji.deviceintegrity.repository.contract.PlayIntegrityRepository
import dev.keiji.deviceintegrity.repository.contract.StandardPlayIntegrityTokenRepository
import dev.keiji.deviceintegrity.repository.contract.exception.ServerException
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
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.IOException

@Config(application = dagger.hilt.android.testing.HiltTestApplication::class)
@RunWith(RobolectricTestRunner::class)
@ExperimentalCoroutinesApi
class StandardPlayIntegrityViewModelTest {

    private val testDispatcher = StandardTestDispatcher()

    private lateinit var viewModel: StandardPlayIntegrityViewModel
    private lateinit var mockPlayIntegrityRepository: PlayIntegrityRepository
    private lateinit var mockStandardPlayIntegrityTokenRepository: StandardPlayIntegrityTokenRepository
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
        mockStandardPlayIntegrityTokenRepository = mock()
        mockDeviceInfoProvider = mock()
        mockDeviceSecurityStateProvider = mock()
        mockAppInfoProvider = mock()

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

        whenever(mockDeviceSecurityStateProvider.isDeviceLockEnabled).thenReturn(true)
        whenever(mockAppInfoProvider.isDebugBuild).thenReturn(false)

        viewModel = StandardPlayIntegrityViewModel(
            mockStandardPlayIntegrityTokenRepository,
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
    fun `fetchIntegrityToken success updates uiState with token`() = runTest {
        val token = "test-standard-token"
        viewModel.updateContentBinding("testContent") // Set content binding
        // Assuming getToken might use the contentBinding to generate a hash
        whenever(mockStandardPlayIntegrityTokenRepository.getToken(any())).thenReturn(token)

        viewModel.fetchIntegrityToken()
        testDispatcher.scheduler.advanceUntilIdle()

        val uiState = viewModel.uiState.first()
        assertEquals(token, uiState.integrityToken)
        assertTrue(uiState.status.contains("Token fetched successfully (Standard API"))
        assertTrue(uiState.requestHashValue.isNotBlank()) // Hash should be generated
    }

    @Test
    fun `verifyToken success updates uiState with response`() = runTest {
        val token = "test-standard-token"
        val contentBinding = "testContent"
        viewModel.updateContentBinding(contentBinding)

        // Simulate fetchIntegrityToken completing and setting currentSessionId
        whenever(mockStandardPlayIntegrityTokenRepository.getToken(any())).thenReturn(token)
        viewModel.fetchIntegrityToken()
        testDispatcher.scheduler.advanceUntilIdle() // Ensure token and session ID are set

        whenever(mockPlayIntegrityRepository.verifyTokenStandard(any(), any(), any(), any(), any()))
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
        val token = "test-standard-token"
        val contentBinding = "testContent"
        viewModel.updateContentBinding(contentBinding)
        whenever(mockStandardPlayIntegrityTokenRepository.getToken(any())).thenReturn(token)
        viewModel.fetchIntegrityToken()
        testDispatcher.scheduler.advanceUntilIdle()

        val serverException = ServerException(400, "Bad Request from server")
        whenever(mockPlayIntegrityRepository.verifyTokenStandard(any(), any(), any(), any(), any()))
            .thenThrow(serverException)

        viewModel.verifyToken()
        testDispatcher.scheduler.advanceUntilIdle()

        val uiState = viewModel.uiState.first()
        assertEquals("Server error verifying token.", uiState.status)
        assertTrue(uiState.errorMessages.isNotEmpty())
        assertEquals("Server error: 400 - Bad Request from server", uiState.errorMessages.first())
    }

    @Test
    fun `verifyToken ioException updates uiState with error`() = runTest {
        val token = "test-standard-token"
        val contentBinding = "testContent"
        viewModel.updateContentBinding(contentBinding)
        whenever(mockStandardPlayIntegrityTokenRepository.getToken(any())).thenReturn(token)
        viewModel.fetchIntegrityToken()
        testDispatcher.scheduler.advanceUntilIdle()

        val ioException = IOException("No internet")
        whenever(mockPlayIntegrityRepository.verifyTokenStandard(any(), any(), any(), any(), any()))
            .thenThrow(ioException)

        viewModel.verifyToken()
        testDispatcher.scheduler.advanceUntilIdle()

        val uiState = viewModel.uiState.first()
        assertEquals("Network error verifying token.", uiState.status)
        assertTrue(uiState.errorMessages.isNotEmpty())
        assertEquals("No internet", uiState.errorMessages.first())
    }
}
