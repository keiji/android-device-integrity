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
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.security.MessageDigest
import android.util.Base64
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

    fun updateContentBinding(newContent: String) {
        _uiState.update {
            it.copy(
                contentBinding = newContent,
                requestHashValue = ""
            )
        }
    }

    fun fetchIntegrityToken() {
        val currentContent = _uiState.value.contentBinding
        // Standard API might allow empty contentBinding for token request,
        // but the calculated property isRequestTokenButtonEnabled handles UI enablement.
        // We proceed with fetching if the button was somehow clicked despite being disabled by UI.

        var encodedHash = ""
        if (currentContent.isNotEmpty()) {
            try {
                val digest = MessageDigest.getInstance("SHA-256")
                val hashBytes = digest.digest(currentContent.toByteArray(Charsets.UTF_8))
                encodedHash = Base64.encodeToString(hashBytes, Base64.NO_WRAP)
            } catch (e: Exception) {
                Log.e("StandardPlayIntegrityVM", "Error generating SHA-256 hash", e)
                // Handle hash generation failure if necessary, though unlikely with SHA-256
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
                val token = standardPlayIntegrityTokenRepository.getToken(currentContent)
                Log.d("StandardPlayIntegrityVM", "Integrity Token (Standard): $token")
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        integrityToken = token,
                        status = "Token fetched successfully (Standard API, see Logcat for token)",
                        errorMessages = emptyList(),
                        requestHashValue = if (currentContent.isNotEmpty()) encodedHash else ""
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
                isLoading = true,
                status = "Verifying token...",
                errorMessages = emptyList(),
                standardVerifyResponse = null
            )
        }

        val contentBindingForVerification = _uiState.value.contentBinding

        viewModelScope.launch {
            try {
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
                        errorMessages = emptyList()
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
