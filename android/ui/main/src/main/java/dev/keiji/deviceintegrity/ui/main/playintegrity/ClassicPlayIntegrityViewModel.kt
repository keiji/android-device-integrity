package dev.keiji.deviceintegrity.ui.main.playintegrity

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.deviceintegrity.api.playintegrity.CreateNonceRequest // Import
import dev.keiji.deviceintegrity.api.playintegrity.PlayIntegrityTokenVerifyApiClient
import dev.keiji.deviceintegrity.api.playintegrity.VerifyTokenRequest
import dev.keiji.deviceintegrity.provider.contract.DeviceInfoProvider
import dev.keiji.deviceintegrity.provider.contract.DeviceSecurityStateProvider
import dev.keiji.deviceintegrity.repository.contract.ClassicPlayIntegrityTokenRepository
import dev.keiji.deviceintegrity.api.playintegrity.DeviceInfo // Added
import dev.keiji.deviceintegrity.api.playintegrity.SecurityInfo // Added
import dev.keiji.deviceintegrity.common.VERIFY_TOKEN_DELAY_MS // Added constant
import kotlinx.coroutines.delay // Added for 20-second delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.UUID // Import
import javax.inject.Inject

@HiltViewModel
class ClassicPlayIntegrityViewModel @Inject constructor(
    private val classicPlayIntegrityTokenRepository: ClassicPlayIntegrityTokenRepository,
    private val playIntegrityTokenVerifyApi: PlayIntegrityTokenVerifyApiClient,
    private val deviceInfoProvider: DeviceInfoProvider,
    private val deviceSecurityStateProvider: DeviceSecurityStateProvider
) : ViewModel() {
    private val _uiState = MutableStateFlow(ClassicPlayIntegrityUiState())
    val uiState: StateFlow<ClassicPlayIntegrityUiState> = _uiState.asStateFlow()

    private var currentSessionId: String = "" // Renamed and initialized as empty

    fun fetchNonce() {
        currentSessionId = UUID.randomUUID().toString() // Generate and assign sessionId here
        _uiState.update {
            it.copy(
                isLoading = true,
                status = "Fetching nonce from server..."
            )
        }
        viewModelScope.launch {
            try {
                val request = CreateNonceRequest(sessionId = currentSessionId) // Use currentSessionId
                val response = playIntegrityTokenVerifyApi.getNonce(request)
                _uiState.update {
                    it.copy(
                        nonce = response.nonce,
                        isLoading = false,
                        status = "Nonce fetched: ${response.nonce}",
                        currentSessionId = currentSessionId
                    )
                }
            } catch (e: Exception) {
                Log.e("ClassicPlayIntegrityVM", "Error fetching nonce", e)
                _uiState.update {
                    it.copy(
                        isLoading = false,
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
                    isLoading = false,
                    status = "Nonce cannot be empty.",
                    errorMessages = listOf("Nonce is required to fetch a token.")
                )
            }
            return
        }

        _uiState.update {
            it.copy(
                isLoading = true,
                status = "Fetching token...",
                errorMessages = emptyList(),
                verifyTokenResponse = null
            )
        }
        viewModelScope.launch {
            try {
                val token = classicPlayIntegrityTokenRepository.getToken(currentNonce)
                Log.d("ClassicPlayIntegrityVM", "Integrity Token: $token")
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        integrityToken = token,
                        status = "Token fetched successfully (see Logcat for token)",
                        errorMessages = emptyList()
                    )
                }
            } catch (e: Exception) {
                Log.e("ClassicPlayIntegrityVM", "Error fetching integrity token", e)
                _uiState.update {
                    it.copy(
                        isLoading = false,
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
                isLoading = true,
                status = "Verifying token with server...", // Original status
                errorMessages = emptyList(),
                verifyTokenResponse = null
            )
        }

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

                val verifyRequest = VerifyTokenRequest(
                    token = token,
                    sessionId = currentSessionId, // Use currentSessionId
                    deviceInfo = deviceInfo,
                    securityInfo = securityInfo
                )
                val verifyResponse = playIntegrityTokenVerifyApi.verifyToken(verifyRequest)

                Log.d("ClassicPlayIntegrityVM", "Verification Response: ${verifyResponse.tokenPayloadExternal}")

                _uiState.update {
                    it.copy(
                        isLoading = false,
                        status = "Token verification complete.",
                        verifyTokenResponse = verifyResponse,
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
                        isLoading = false,
                        status = "Error verifying token with server.",
                        errorMessages = listOf(errorMessage),
                        verifyTokenResponse = null // Clear previous response on error
                    )
                }
            }
        }
    }
}
