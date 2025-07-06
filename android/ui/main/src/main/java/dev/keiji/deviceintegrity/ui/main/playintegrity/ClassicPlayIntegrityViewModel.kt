package dev.keiji.deviceintegrity.ui.main.playintegrity

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.deviceintegrity.api.playintegrity.DeviceInfo
import dev.keiji.deviceintegrity.api.playintegrity.SecurityInfo
import dev.keiji.deviceintegrity.api.playintegrity.VerifyTokenRequest
import dev.keiji.deviceintegrity.provider.contract.AppInfoProvider
import dev.keiji.deviceintegrity.provider.contract.DeviceInfoProvider
import dev.keiji.deviceintegrity.provider.contract.DeviceSecurityStateProvider
import dev.keiji.deviceintegrity.provider.contract.GooglePlayDeveloperServiceInfoProvider
import dev.keiji.deviceintegrity.repository.contract.ClassicPlayIntegrityTokenRepository
import dev.keiji.deviceintegrity.repository.contract.PlayIntegrityRepository
import dev.keiji.deviceintegrity.repository.contract.exception.ServerException
import dev.keiji.deviceintegrity.ui.main.common.DEBUG_VERIFY_TOKEN_DELAY_MS
import dev.keiji.deviceintegrity.ui.main.common.VERIFY_TOKEN_DELAY_MS
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.io.IOException
import java.util.UUID
import javax.inject.Inject

// PlayIntegrityProgressConstants will be imported from the new common file

@HiltViewModel
class ClassicPlayIntegrityViewModel @Inject constructor(
    private val classicPlayIntegrityTokenRepository: ClassicPlayIntegrityTokenRepository,
    private val playIntegrityRepository: PlayIntegrityRepository,
    private val deviceInfoProvider: DeviceInfoProvider,
    private val deviceSecurityStateProvider: DeviceSecurityStateProvider,
    private val googlePlayDeveloperServiceInfoProvider: GooglePlayDeveloperServiceInfoProvider,
    private val appInfoProvider: AppInfoProvider
) : ViewModel() {
    private val _uiState = MutableStateFlow(ClassicPlayIntegrityUiState())
    val uiState: StateFlow<ClassicPlayIntegrityUiState> = _uiState.asStateFlow()

    private var currentSessionId: String = "" // Renamed and initialized as empty

    init {
        viewModelScope.launch {
            val info = googlePlayDeveloperServiceInfoProvider.provide()
             _uiState.update { it.copy(googlePlayDeveloperServiceInfo = info) }
        }
    }

    fun fetchNonce() {
        currentSessionId = UUID.randomUUID().toString() // Generate and assign sessionId here
        _uiState.update {
            it.copy(
                integrityToken = "", // Clear previous integrity token
                progressValue = PlayIntegrityProgressConstants.FULL_PROGRESS, // Start ProgressBar at full for nonce fetching
                status = "Fetching nonce from server...",
                serverVerificationPayload = null,
                errorMessages = emptyList()
            )
        }
        viewModelScope.launch {
            try {
                // Simulate delay for fetching nonce with progress updates
                val delayMs = VERIFY_TOKEN_DELAY_MS // Using existing constant for delay
                val totalSteps =
                    (delayMs / PlayIntegrityProgressConstants.PROGRESS_UPDATE_INTERVAL_MS).toInt()
                var currentStep = 0

                while (currentStep < totalSteps) {
                    delay(PlayIntegrityProgressConstants.PROGRESS_UPDATE_INTERVAL_MS) // Wait
                    currentStep++
                    // Calculate progress, but don't coerce to NO_PROGRESS here if it's the last step,
                    // as we will immediately switch to INDETERMINATE_PROGRESS.
                    // For intermediate steps, it can still be updated.
                    if (currentStep < totalSteps) {
                        val newProgress =
                            PlayIntegrityProgressConstants.FULL_PROGRESS - (currentStep.toFloat() / totalSteps)
                        _uiState.update { currentState ->
                            currentState.copy(
                                progressValue = newProgress.coerceAtLeast(PlayIntegrityProgressConstants.NO_PROGRESS)
                            )
                        }
                    }
                }

                // Directly update to indeterminate after the loop, ensuring no 0.0F state if loop completes.
                _uiState.update { it.copy(
                    progressValue = PlayIntegrityProgressConstants.INDETERMINATE_PROGRESS,
                    status = "Finalizing nonce request..."
                ) }

                val response = playIntegrityRepository.getNonce(currentSessionId)
                _uiState.update {
                    it.copy(
                        nonce = response.nonce,
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS, // Ensure NO_PROGRESS on success
                        status = "Nonce fetched: ${response.nonce}",
                        currentSessionId = currentSessionId
                    )
                }
            } catch (e: ServerException) { // Catch ServerException
                Log.e(
                    "ClassicPlayIntegrityVM",
                    "Server error fetching nonce: ${e.errorCode} - ${e.errorMessage}",
                    e
                )
                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS,
                        status = "Server error fetching nonce.",
                        errorMessages = listOf("Server error: ${e.errorCode ?: "N/A"} - ${e.errorMessage ?: "Unknown"}"),
                    )
                }
            } catch (e: IOException) { // Catch IOException
                Log.e("ClassicPlayIntegrityVM", "Network error fetching nonce", e)
                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS,
                        status = "Network error fetching nonce.",
                        errorMessages = listOf(e.message ?: "Unknown network error."),
                    )
                }
            } catch (e: Exception) { // Catch other exceptions
                Log.e("ClassicPlayIntegrityVM", "Unknown error fetching nonce", e)
                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS,
                        status = "Unknown error fetching nonce.",
                        errorMessages = listOf(e.message ?: "An unexpected error occurred."),
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
                serverVerificationPayload = null
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
                serverVerificationPayload = null
            )
        }

        viewModelScope.launch {
            try {
                val delayMs =
                    if (appInfoProvider.isDebugBuild) DEBUG_VERIFY_TOKEN_DELAY_MS else VERIFY_TOKEN_DELAY_MS
                val totalSteps =
                    (delayMs / PlayIntegrityProgressConstants.PROGRESS_UPDATE_INTERVAL_MS).toInt()
                var currentStep = 0

                // Update status to indicate waiting period and switch to ProgressBar
                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.FULL_PROGRESS, // Start ProgressBar at full
                        status = "Waiting for ${delayMs / 1000} seconds before verification..."
                    )
                }

                while (currentStep < totalSteps) {
                    delay(PlayIntegrityProgressConstants.PROGRESS_UPDATE_INTERVAL_MS) // Wait
                    currentStep++
                    val newProgress =
                        PlayIntegrityProgressConstants.FULL_PROGRESS - (currentStep.toFloat() / totalSteps)
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

                // Fetch GooglePlayDeveloperServiceInfo directly when needed
                val googlePlayDeveloperServiceInfo = googlePlayDeveloperServiceInfoProvider.provide()

                val verifyResponse =
                    playIntegrityRepository.verifyTokenClassic( // Use repository
                        integrityToken = token,
                        sessionId = currentSessionId,
                        deviceInfo = deviceInfoData,
                        securityInfo = securityInfo,
                        googlePlayDeveloperServiceInfo = googlePlayDeveloperServiceInfo // Pass the fetched info
                    )

                Log.d(
                    "ClassicPlayIntegrityVM",
                    "Verification Response: ${verifyResponse.playIntegrityResponse.tokenPayloadExternal}"
                )

                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS,
                        status = "Token verification complete.",
                        serverVerificationPayload = verifyResponse, // Store the whole payload
                        errorMessages = emptyList(),
                        currentSessionId = currentSessionId
                    )
                }
            } catch (e: ServerException) { // Catch ServerException
                Log.e(
                    "ClassicPlayIntegrityVM",
                    "Server error verifying token: ${e.errorCode} - ${e.errorMessage}",
                    e
                )
                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS,
                        status = "Server error verifying token.",
                        errorMessages = listOf("Server error: ${e.errorCode ?: "N/A"} - ${e.errorMessage ?: "Unknown"}"),
                        serverVerificationPayload = null
                    )
                }
            } catch (e: IOException) { // Catch IOException
                Log.e("ClassicPlayIntegrityVM", "Network error verifying token", e)
                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS,
                        status = "Network error verifying token.",
                        errorMessages = listOf(e.message ?: "Unknown network error."),
                        serverVerificationPayload = null
                    )
                }
            } catch (e: Exception) { // Catch other exceptions
                Log.e("ClassicPlayIntegrityVM", "Unknown error verifying token", e)
                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS,
                        status = "Unknown error verifying token.${e.javaClass.simpleName} ${e.stackTraceToString()}",
                        errorMessages = listOf(e.message ?: "An unexpected error occurred."),
                        serverVerificationPayload = null
                    )
                }
            }
        }
    }
}
