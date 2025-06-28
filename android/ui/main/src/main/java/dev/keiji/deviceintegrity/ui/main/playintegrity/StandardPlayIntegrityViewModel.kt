package dev.keiji.deviceintegrity.ui.main.playintegrity

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.deviceintegrity.api.playintegrity.PlayIntegrityTokenVerifyApiClient
import dev.keiji.deviceintegrity.api.playintegrity.StandardVerifyRequest
import dev.keiji.deviceintegrity.api.playintegrity.TokenPayloadExternal
import dev.keiji.deviceintegrity.provider.contract.DeviceInfoProvider
import dev.keiji.deviceintegrity.provider.contract.DeviceSecurityStateProvider
import dev.keiji.deviceintegrity.repository.contract.StandardPlayIntegrityTokenRepository
import dev.keiji.deviceintegrity.api.playintegrity.DeviceInfo // Added
import dev.keiji.deviceintegrity.api.playintegrity.SecurityInfo // Added
import dev.keiji.deviceintegrity.ui.main.common.VERIFY_TOKEN_DELAY_MS // Updated import
import kotlinx.coroutines.delay // Added for 20-second delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.security.MessageDigest
import android.util.Base64
import java.util.UUID
import javax.inject.Inject

@HiltViewModel
class StandardPlayIntegrityViewModel @Inject constructor(
    private val standardPlayIntegrityTokenRepository: StandardPlayIntegrityTokenRepository,
    private val playIntegrityTokenVerifyApiClient: PlayIntegrityTokenVerifyApiClient,
    private val deviceInfoProvider: DeviceInfoProvider,
    private val deviceSecurityStateProvider: DeviceSecurityStateProvider
) : ViewModel() {
    private val _uiState = MutableStateFlow(StandardPlayIntegrityUiState())
    val uiState: StateFlow<StandardPlayIntegrityUiState> = _uiState.asStateFlow()

    private var currentSessionId: String = "" // Initialized as empty

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
                isLoading = true,
                status = "Fetching token...",
                requestHashValue = "" // Reset before attempting to fetch
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
                        isLoading = false,
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
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        status = "Error fetching integrity token (Standard).",
                        errorMessages = listOfNotNull(e.message),
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
                isLoading = true,
                status = "Verifying token...", // Original status
                errorMessages = emptyList(),
                standardVerifyResponse = null
            )
        }

        val contentBindingForVerification = currentUiState.contentBinding

        viewModelScope.launch {
            try {
                // Update status to indicate waiting period
                _uiState.update {
                    it.copy(
                        status = "Waiting for 20 seconds before verification..."
                    )
                }

                delay(VERIFY_TOKEN_DELAY_MS) // Used constant

                // Update status before actual verification
                _uiState.update {
                    it.copy(
                        status = "Now verifying token with server..."
                    )
                }

                val deviceInfo = DeviceInfo(
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

                val request = StandardVerifyRequest(
                    token = token,
                    sessionId = currentSessionId, // Use ViewModel's currentSessionId field
                    contentBinding = contentBindingForVerification,
                    deviceInfo = deviceInfo,
                    securityInfo = securityInfo
                )
                val response = playIntegrityTokenVerifyApiClient.verifyTokenStandard(request)

                Log.d("StandardPlayIntegrityVM", "Verification Response: ${response.tokenPayloadExternal}")

                _uiState.update {
                    it.copy(
                        isLoading = false,
                        status = "Token verification complete.",
                        standardVerifyResponse = response,
                        errorMessages = emptyList(),
                        currentSessionId = currentSessionId
                    )
                }
            } catch (e: Exception) {
                Log.e("StandardPlayIntegrityVM", "Error verifying token with server", e)
                val errorMessage = e.message ?: "Unknown error during verification"
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        status = "Error verifying token with server.",
                        errorMessages = listOf(errorMessage),
                        standardVerifyResponse = null // Clear previous response on error
                    )
                }
            }
        }
    }
}
