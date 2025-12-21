package dev.keiji.deviceintegrity.ui.express_mode

import dev.keiji.deviceintegrity.api.DeviceInfo
import dev.keiji.deviceintegrity.api.SecurityInfo
import dev.keiji.deviceintegrity.api.keyattestation.AttestationInfo
import dev.keiji.deviceintegrity.api.keyattestation.AuthorizationList
import dev.keiji.deviceintegrity.api.keyattestation.PrepareResponse
import dev.keiji.deviceintegrity.api.keyattestation.VerifySignatureResponse
import dev.keiji.deviceintegrity.api.playintegrity.PlayIntegrityResponseWrapper
import dev.keiji.deviceintegrity.api.playintegrity.ServerVerificationPayload
import dev.keiji.deviceintegrity.api.playintegrity.TokenPayloadExternal
import dev.keiji.deviceintegrity.crypto.contract.Signer
import dev.keiji.deviceintegrity.provider.contract.AppInfoProvider
import dev.keiji.deviceintegrity.provider.contract.DeviceInfoProvider
import dev.keiji.deviceintegrity.provider.contract.DeviceSecurityStateProvider
import dev.keiji.deviceintegrity.provider.contract.GooglePlayDeveloperServiceInfoProvider
import dev.keiji.deviceintegrity.repository.contract.KeyAttestationRepository
import dev.keiji.deviceintegrity.repository.contract.KeyPairData
import dev.keiji.deviceintegrity.repository.contract.KeyPairRepository
import dev.keiji.deviceintegrity.repository.contract.PlayIntegrityRepository
import dev.keiji.deviceintegrity.repository.contract.StandardPlayIntegrityTokenRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.kotlin.any
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import org.robolectric.RobolectricTestRunner
import java.security.KeyPair
import java.security.PrivateKey
import java.security.cert.X509Certificate

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class ExpressModeViewModelTest {

    private val dispatcher = StandardTestDispatcher()

    private val standardPlayIntegrityTokenRepository: StandardPlayIntegrityTokenRepository = mock()
    private val playIntegrityRepository: PlayIntegrityRepository = mock()
    private val keyPairRepository: KeyPairRepository = mock()
    private val keyAttestationRepository: KeyAttestationRepository = mock()
    private val deviceInfoProvider: DeviceInfoProvider = mock()
    private val deviceSecurityStateProvider: DeviceSecurityStateProvider = mock()
    private val googlePlayDeveloperServiceInfoProvider: GooglePlayDeveloperServiceInfoProvider = mock()
    private val appInfoProvider: AppInfoProvider = mock()
    private val ecSigner: Signer = mock()

    @Before
    fun setUp() {
        Dispatchers.setMain(dispatcher)

        whenever(deviceInfoProvider.BRAND).thenReturn("TestBrand")
        whenever(deviceInfoProvider.MODEL).thenReturn("TestModel")
        whenever(deviceInfoProvider.DEVICE).thenReturn("TestDevice")
        whenever(deviceInfoProvider.PRODUCT).thenReturn("TestProduct")
        whenever(deviceInfoProvider.MANUFACTURER).thenReturn("TestManufacturer")
        whenever(deviceInfoProvider.HARDWARE).thenReturn("TestHardware")
        whenever(deviceInfoProvider.BOARD).thenReturn("TestBoard")
        whenever(deviceInfoProvider.BOOTLOADER).thenReturn("TestBootloader")
        whenever(deviceInfoProvider.VERSION_RELEASE).thenReturn("TestRelease")
        whenever(deviceInfoProvider.SDK_INT).thenReturn(33)
        whenever(deviceInfoProvider.FINGERPRINT).thenReturn("TestFingerprint")
        whenever(deviceInfoProvider.SECURITY_PATCH).thenReturn("TestPatch")

        whenever(deviceSecurityStateProvider.isDeviceLockEnabled).thenReturn(true)
        whenever(deviceSecurityStateProvider.isBiometricsEnabled).thenReturn(false)
        whenever(deviceSecurityStateProvider.hasClass3Authenticator).thenReturn(false)
        whenever(deviceSecurityStateProvider.hasStrongBox).thenReturn(false)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `verification flow runs successfully`() = runTest(dispatcher) {
        // Setup Mocks
        whenever(standardPlayIntegrityTokenRepository.getToken(anyOrNull())).thenReturn("test_token")

        val mockDeviceInfo = DeviceInfo(
             "b", "m", "d", "p", "m", "h", "b", "b", "v", 33, "f", "s"
        )
        val mockSecurityInfo = SecurityInfo(
            true, false, false, false
        )

        val mockPayload = ServerVerificationPayload(
            playIntegrityResponse = PlayIntegrityResponseWrapper(
                tokenPayloadExternal = TokenPayloadExternal(null, null, null, null)
            ),
            deviceInfo = mockDeviceInfo,
            securityInfo = mockSecurityInfo
        )
        whenever(playIntegrityRepository.verifyTokenStandard(any(), any(), any(), any(), any(), anyOrNull())).thenReturn(mockPayload)

        whenever(keyAttestationRepository.prepareSignature()).thenReturn(
            PrepareResponse(
                "session_id", "nonce_b64", "challenge_b64"
            )
        )

        val mockKeyPair = mock<KeyPair>()
        val mockPrivateKey = mock<PrivateKey>()
        whenever(mockKeyPair.private).thenReturn(mockPrivateKey)
        val mockCert = mock<X509Certificate>()
        whenever(mockCert.encoded).thenReturn(byteArrayOf(1, 2, 3))

        val mockKeyPairData = KeyPairData("alias", arrayOf(mockCert), mockKeyPair)

        whenever(keyPairRepository.generateEcKeyPair(any(), any(), any())).thenReturn(mockKeyPairData)
        whenever(ecSigner.sign(any(), any())).thenReturn(byteArrayOf(4, 5, 6))

        val mockAttestationInfo = AttestationInfo(
            attestationSecurityLevel = 1,
            attestationVersion = 1,
            keymintSecurityLevel = 1,
            keymintVersion = 1,
            attestationChallenge = "challenge",
            softwareEnforcedProperties = AuthorizationList(),
            hardwareEnforcedProperties = AuthorizationList()
        )

        val mockVerifyResponse = VerifySignatureResponse(
            isVerified = true,
            sessionId = "session_id",
            attestationInfo = mockAttestationInfo,
            deviceInfo = mockDeviceInfo,
            securityInfo = mockSecurityInfo,
            certificateChain = emptyList()
        )
        whenever(keyAttestationRepository.verifySignature(any())).thenReturn(mockVerifyResponse)

        // Create ViewModel
        val viewModel = ExpressModeViewModel(
            standardPlayIntegrityTokenRepository,
            playIntegrityRepository,
            keyPairRepository,
            keyAttestationRepository,
            deviceInfoProvider,
            deviceSecurityStateProvider,
            googlePlayDeveloperServiceInfoProvider,
            appInfoProvider,
            ecSigner
        )

        // Advance past delay
        advanceUntilIdle()

        // Verify final state
        val state = viewModel.uiState.value
        println("Final State Status: ${state.status}")
        assert(state.status == "Verification Complete")
        assert(state.playIntegrityInfoItems.isNotEmpty())
        assert(state.keyAttestationInfoItems.isNotEmpty())
    }
}
