package dev.keiji.deviceintegrity.ui.main.playintegrity

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.deviceintegrity.provider.contract.AppInfoProvider
import dev.keiji.deviceintegrity.provider.contract.DeviceInfoProvider
import dev.keiji.deviceintegrity.provider.contract.DeviceSecurityStateProvider
import dev.keiji.deviceintegrity.provider.contract.GooglePlayDeveloperServiceInfoProvider
import dev.keiji.deviceintegrity.repository.contract.StandardPlayIntegrityTokenRepository
import dev.keiji.deviceintegrity.repository.contract.PlayIntegrityRepository // Added
import dev.keiji.deviceintegrity.repository.contract.exception.ServerException // Corrected path
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
import java.security.MessageDigest
import android.util.Base64
import java.io.IOException // Added
import java.util.UUID
import javax.inject.Inject

// PlayIntegrityProgressConstants will be imported from the new common file

@HiltViewModel
class StandardPlayIntegrityViewModel @Inject constructor(
    private val standardPlayIntegrityTokenRepository: StandardPlayIntegrityTokenRepository,
    private val playIntegrityRepository: PlayIntegrityRepository, // Changed
    private val deviceInfoProvider: DeviceInfoProvider,
    private val deviceSecurityStateProvider: DeviceSecurityStateProvider,
    private val googlePlayDeveloperServiceInfoProvider: GooglePlayDeveloperServiceInfoProvider,
    private val appInfoProvider: AppInfoProvider
) : ViewModel() {
    private val _uiState = MutableStateFlow(StandardPlayIntegrityUiState())
    val uiState: StateFlow<StandardPlayIntegrityUiState> = _uiState.asStateFlow()

    private var currentSessionId: String = "" // Initialized as empty

    init {
        viewModelScope.launch {
            val info = googlePlayDeveloperServiceInfoProvider.provide()
            _uiState.update { it.copy(googlePlayDeveloperServiceInfo = info) }
        }
    }

    fun updateContentBinding(newContent: String) {
        _uiState.update {
            it.copy(
                contentBinding = newContent,
                requestHashValue = ""
            )
        }
    }

    fun fetchIntegrityToken() {
        currentSessionId = UUID.randomUUID().toString() // Generate and assign sessionId here

        val currentContent = _uiState.value.contentBinding
        // Standard API might allow empty contentBinding for token request,
        // but the calculated property isRequestTokenButtonEnabled handles UI enablement.
        // We proceed with fetching if the button was somehow clicked despite being disabled by UI.

        var encodedHash = ""
        // contentBinding might be empty, but we still need to include currentSessionId in the hash if we were to create one.
        // However, the original logic only created a hash if currentContent was not empty.
        // For consistency with the requirement "sessionId + contentBinding", we'll prepare the string for hashing.
        // The actual decision to *use* the hash (i.e., pass it to getToken) depends on whether contentBinding is empty.
        val stringToHash = currentSessionId + currentContent

        if (stringToHash.isNotEmpty()) { // Or simply if currentContent.isNotEmpty() if requestHash is only for non-empty contentBinding
            try {
                val digest = MessageDigest.getInstance("SHA-256")
                // Ensure UTF-8 encoding for consistent hashing across platforms
                val hashBytes = digest.digest(stringToHash.toByteArray(Charsets.UTF_8))
                // Use URL_SAFE, NO_WRAP, and NO_PADDING for Play Integrity API compatibility
                encodedHash = Base64.encodeToString(hashBytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            } catch (e: Exception) {
                Log.e("StandardPlayIntegrityVM", "Error generating SHA-256 hash for '$stringToHash'", e)
                // Handle hash generation failure
            }
        }

        _uiState.update {
            it.copy(
                progressValue = PlayIntegrityProgressConstants.INDETERMINATE_PROGRESS,
                status = "Fetching token...",
                requestHashValue = "", // Reset before attempting to fetch
                errorMessages = emptyList(), // Clear previous errors
                playIntegrityResponse = null, // Clear previous response
                deviceInfo = null,
                securityInfo = null
            )
        }
        viewModelScope.launch {
            try {
                // Pass the potentially empty currentContent, the repository handles the requestHash logic.
                // The `encodedHash` calculated above is based on `sessionId + currentContent`.
                // The `standardPlayIntegrityTokenRepository.getToken` will internally use this `encodedHash`
                // if `currentContent` is not empty. We need to ensure the repository is updated to expect
                // a hash derived from `sessionId + contentBinding` if `contentBinding` is provided.
                // For now, we are ensuring `encodedHash` is correctly calculated here.
                // The `getToken` method will be updated to accept the pre-calculated hash.
                // Based on the current plan, the app (ViewModel) calculates the hash.
                // If contentBinding is empty, encodedHash will be based on sessionId only.
                // If contentBinding is also empty, requestHash should not be set.
                // The original repo logic set requestHash only if contentToBind was not null.
                // We will pass encodedHash if currentContent is not empty, otherwise null.
                val hashToPass = if (currentContent.isNotEmpty()) encodedHash else null
                val token = standardPlayIntegrityTokenRepository.getToken(hashToPass)
                Log.d("StandardPlayIntegrityVM", "Integrity Token (Standard): $token")
                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS,
                        integrityToken = token,
                        status = "Token fetched successfully (Standard API, see Logcat for token)",
                        errorMessages = emptyList(),
                        // Display the hash if it was generated (i.e., if stringToHash was not empty, implies currentContent was not empty based on original logic)
                        requestHashValue = if (currentContent.isNotEmpty()) encodedHash else "",
                        currentSessionId = currentSessionId
                    )
                }
            } catch (e: Exception) {
                Log.e("StandardPlayIntegrityVM", "Error fetching integrity token (Standard)", e)
                val errorMessage = if (e is ServerException) {
                    val errorBody = e.errorMessage ?: "No additional error information."
                    "Error fetching integrity token (Standard): ${e.errorCode} - $errorBody"
                } else {
                    e.message ?: "Unknown error fetching integrity token (Standard)."
                }
                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS,
                        status = "Error fetching integrity token (Standard).",
                        errorMessages = listOf(errorMessage),
                        requestHashValue = ""
                    )
                }
            }
        }
    }

    fun verifyToken() {
        val currentUiState = _uiState.value
        val token = currentUiState.integrityToken

        if (token.isBlank()) {
            _uiState.update {
                it.copy(
                    status = "Token not available for verification.",
                    errorMessages = listOf("Token is required for verification.")
                )
            }
            return
        }

        if (currentSessionId.isBlank()) { // Use ViewModel's currentSessionId field
            // This case should ideally not happen if fetchIntegrityToken was successful
            _uiState.update {
                it.copy(
                    status = "Session ID not available for verification.",
                    errorMessages = listOf("Session ID is missing.")
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

        val contentBindingForVerification = currentUiState.contentBinding

        viewModelScope.launch {
            try {
                val delayMs = if (appInfoProvider.isDebugBuild) DEBUG_VERIFY_TOKEN_DELAY_MS else VERIFY_TOKEN_DELAY_MS
                val totalSteps = (delayMs / PlayIntegrityProgressConstants.PROGRESS_UPDATE_INTERVAL_MS).toInt()
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
                    val newProgress = PlayIntegrityProgressConstants.FULL_PROGRESS - (currentStep.toFloat() / totalSteps)
                    _uiState.update {
                        it.copy(
                            progressValue = newProgress.coerceAtLeast(PlayIntegrityProgressConstants.NO_PROGRESS)
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

                val response = playIntegrityRepository.verifyTokenStandard( // Use repository
                    integrityToken = token,
                    sessionId = currentSessionId,
                    contentBinding = contentBindingForVerification,
                    deviceInfo = deviceInfoData,
                    securityInfo = securityInfo,
                    googlePlayDeveloperServiceInfo = _uiState.value.googlePlayDeveloperServiceInfo
                )

                Log.d("StandardPlayIntegrityVM", "Verification Response: ${response.playIntegrityResponse.tokenPayloadExternal}")

                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS,
                        status = "Token verification complete.",
                        playIntegrityResponse = response.playIntegrityResponse.tokenPayloadExternal,
                        deviceInfo = response.deviceInfo,
                        securityInfo = response.securityInfo,
                        errorMessages = emptyList(),
                        currentSessionId = currentSessionId
                    )
                }
            } catch (e: ServerException) { // Catch ServerException
                Log.e("StandardPlayIntegrityVM", "Server error verifying token: ${e.errorCode} - ${e.errorMessage}", e)
                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS,
                        status = "Server error verifying token.",
                        errorMessages = listOf("Server error: ${e.errorCode ?: "N/A"} - ${e.errorMessage ?: "Unknown"}"),
                        playIntegrityResponse = null,
                        deviceInfo = null,
                        securityInfo = null
                    )
                }
            } catch (e: IOException) { // Catch IOException
                Log.e("StandardPlayIntegrityVM", "Network error verifying token", e)
                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS,
                        status = "Network error verifying token.",
                        errorMessages = listOf(e.message ?: "Unknown network error."),
                        playIntegrityResponse = null,
                        deviceInfo = null,
                        securityInfo = null
                    )
                }
            } catch (e: Exception) { // Catch other exceptions
                Log.e("StandardPlayIntegrityVM", "Unknown error verifying token", e)
                _uiState.update {
                    it.copy(
                        progressValue = PlayIntegrityProgressConstants.NO_PROGRESS,
                        status = "Unknown error verifying token.",
                        errorMessages = listOf(e.message ?: "An unexpected error occurred."),
                        playIntegrityResponse = null,
                        deviceInfo = null,
                        securityInfo = null
                    )
                }
            }
        }
    }
}
