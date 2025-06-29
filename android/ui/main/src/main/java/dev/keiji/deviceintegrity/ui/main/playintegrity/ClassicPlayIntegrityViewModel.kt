package dev.keiji.deviceintegrity.ui.main.playintegrity

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.deviceintegrity.api.playintegrity.CreateNonceRequest // Import
import dev.keiji.deviceintegrity.api.playintegrity.PlayIntegrityTokenVerifyApiClient
import dev.keiji.deviceintegrity.api.playintegrity.VerifyTokenRequest
import dev.keiji.deviceintegrity.provider.contract.AppInfoProvider
import dev.keiji.deviceintegrity.provider.contract.DeviceInfoProvider
import dev.keiji.deviceintegrity.provider.contract.DeviceSecurityStateProvider
import dev.keiji.deviceintegrity.repository.contract.ClassicPlayIntegrityTokenRepository
import dev.keiji.deviceintegrity.api.playintegrity.DeviceInfo
import dev.keiji.deviceintegrity.api.playintegrity.SecurityInfo
import dev.keiji.deviceintegrity.ui.main.common.DEBUG_VERIFY_TOKEN_DELAY_MS
import dev.keiji.deviceintegrity.ui.main.common.VERIFY_TOKEN_DELAY_MS
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.UUID // Import
import javax.inject.Inject
// PlayIntegrityProgressConstants will be imported from the new common file

@HiltViewModel
class ClassicPlayIntegrityViewModel @Inject constructor(
    private val classicPlayIntegrityTokenRepository: ClassicPlayIntegrityTokenRepository,
    private val playIntegrityTokenVerifyApi: PlayIntegrityTokenVerifyApiClient,
    private val deviceInfoProvider: DeviceInfoProvider,
    private val deviceSecurityStateProvider: DeviceSecurityStateProvider,
    private val appInfoProvider: AppInfoProvider
) : ViewModel() {
    private val _uiState = MutableStateFlow(ClassicPlayIntegrityUiState())
    val uiState: StateFlow<ClassicPlayIntegrityUiState> = _uiState.asStateFlow()

    private var currentSessionId: String = "" // Renamed and initialized as empty

    fun fetchNonce() {
        currentSessionId = UUID.randomUUID().toString() // Generate and assign sessionId here
        _uiState.update {
            it.copy(
                integrityToken = "", // Clear previous integrity token
                progressValue = PlayIntegrityProgressConstants.INDETERMINATE_PROGRESS,
                status = "Fetching nonce from server..."
            )
        }
        viewModelScope.launch {
            try {
                delay(VERIFY_TOKEN_DELAY_MS)

                val request = CreateNonceRequest(sessionId = currentSessionId) // Use currentSessionId
                val response = playIntegrityTokenVerifyApi.getNonce(request)
                _uiState.update {
                    it.copy(
                        nonce = response.nonce,
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS,
                        status = "Nonce fetched: ${response.nonce}",
                        currentSessionId = currentSessionId
                    )
                }
            } catch (e: Exception) {
                Log.e("ClassicPlayIntegrityVM", "Error fetching nonce", e)
                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS,
                        status = "Error fetching nonce.",
                        errorMessages = listOfNotNull(e.message)
                    )
                }
            }
        }
    }

    fun updateNonce(newNonce: String) {
        _uiState.update { it.copy(nonce = newNonce, errorMessages = emptyList()) }
    }

    fun fetchIntegrityToken() {
        val currentNonce = _uiState.value.nonce
        if (currentNonce.isBlank()) {
            _uiState.update {
                it.copy(
                    // isLoading = false, // Not strictly necessary to change here as it's not set to true
                    status = "Nonce cannot be empty.",
                    errorMessages = listOf("Nonce is required to fetch a token.")
                )
            }
            return
        }

        _uiState.update {
            it.copy(
                progressValue = PlayIntegrityProgressConstants.INDETERMINATE_PROGRESS,
                status = "Fetching token...",
                errorMessages = emptyList(),
                playIntegrityResponse = null
            )
        }
        viewModelScope.launch {
            try {
                val token = classicPlayIntegrityTokenRepository.getToken(currentNonce)
                Log.d("ClassicPlayIntegrityVM", "Integrity Token: $token")
                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS,
                        integrityToken = token,
                        status = "Token fetched successfully (see Logcat for token)",
                        errorMessages = emptyList()
                    )
                }
            } catch (e: Exception) {
                Log.e("ClassicPlayIntegrityVM", "Error fetching integrity token", e)
                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS,
                        status = "Error fetching integrity token.",
                        errorMessages = listOfNotNull(e.message)
                    )
                }
            }
        }
    }

    fun verifyToken() {
        val token = _uiState.value.integrityToken

        if (token.isBlank()) {
            _uiState.update {
                it.copy(
                    status = "Token not available for verification.",
                    errorMessages = listOf("Token is required for verification.")
                )
            }
            return
        }

        _uiState.update {
            it.copy(
                progressValue = PlayIntegrityProgressConstants.INDETERMINATE_PROGRESS, // Start with CircularProgress
                status = "Preparing to verify token...", // Initial status
                errorMessages = emptyList(),
                playIntegrityResponse = null,
                deviceInfo = null,
                securityInfo = null
            )
        }

        viewModelScope.launch {
            try {
                val delayMs = if (appInfoProvider.isDebugBuild) DEBUG_VERIFY_TOKEN_DELAY_MS else VERIFY_TOKEN_DELAY_MS
                val totalSteps = (delayMs / 100).toInt() // e.g., 200 steps for 20 seconds
                var currentStep = 0

                // Update status to indicate waiting period and switch to ProgressBar
                _uiState.update {
                    it.copy(
                        progressValue = 1.0F, // Start ProgressBar at full
                        status = "Waiting for ${delayMs / 1000} seconds before verification..."
                    )
                }

                while (currentStep < totalSteps) {
                    delay(100) // Wait for 0.1 seconds
                    currentStep++
                    val newProgress = 1.0F - (currentStep.toFloat() / totalSteps)
                    _uiState.update {
                        it.copy(
                            progressValue = newProgress.coerceAtLeast(PlayIntegrityProgressConstants.NO_PROGRESS) // Ensure progress doesn't go below 0
                        )
                    }
                }

                // Update status before actual verification and switch back to CircularProgress
                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.INDETERMINATE_PROGRESS, // Show CircularProgress during actual verification
                        status = "Now verifying token with server..."
                    )
                }

                val deviceInfoData = DeviceInfo(
                    brand = deviceInfoProvider.BRAND,
                    model = deviceInfoProvider.MODEL,
                    device = deviceInfoProvider.DEVICE,
                    product = deviceInfoProvider.PRODUCT,
                    manufacturer = deviceInfoProvider.MANUFACTURER,
                    hardware = deviceInfoProvider.HARDWARE,
                    board = deviceInfoProvider.BOARD,
                    bootloader = deviceInfoProvider.BOOTLOADER,
                    versionRelease = deviceInfoProvider.VERSION_RELEASE,
                    sdkInt = deviceInfoProvider.SDK_INT,
                    fingerprint = deviceInfoProvider.FINGERPRINT,
                    securityPatch = deviceInfoProvider.SECURITY_PATCH
                )

                val securityInfo = SecurityInfo(
                    isDeviceLockEnabled = deviceSecurityStateProvider.isDeviceLockEnabled,
                    isBiometricsEnabled = deviceSecurityStateProvider.isBiometricsEnabled,
                    hasClass3Authenticator = deviceSecurityStateProvider.hasClass3Authenticator,
                    hasStrongbox = deviceSecurityStateProvider.hasStrongBox
                )

                val verifyRequest = VerifyTokenRequest(
                    token = token,
                    sessionId = currentSessionId,
                    deviceInfo = deviceInfoData,
                    securityInfo = securityInfo
                )
                val verifyResponse = playIntegrityTokenVerifyApi.verifyTokenClassic(verifyRequest)

                Log.d("ClassicPlayIntegrityVM", "Verification Response: ${verifyResponse.playIntegrityResponse.tokenPayloadExternal}")

                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS,
                        status = "Token verification complete.",
                        playIntegrityResponse = verifyResponse.playIntegrityResponse.tokenPayloadExternal,
                        deviceInfo = verifyResponse.deviceInfo,
                        securityInfo = verifyResponse.securityInfo,
                        errorMessages = emptyList(),
                        currentSessionId = currentSessionId
                    )
                }
            } catch (e: Exception) {
                Log.e("ClassicPlayIntegrityVM", "Error verifying token with server", e)
                // Consider parsing specific error types if server returns structured errors
                val errorMessage = e.message ?: "Unknown error during verification"
                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS,
                        status = "Error verifying token with server.",
                        errorMessages = listOf(errorMessage),
                        playIntegrityResponse = null,
                        deviceInfo = null,
                        securityInfo = null
                    )
                }
            }
        }
    }
}
