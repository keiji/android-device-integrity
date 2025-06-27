package dev.keiji.deviceintegrity.ui.main.playintegrity

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.deviceintegrity.api.playintegrity.PlayIntegrityTokenVerifyApiClient
import dev.keiji.deviceintegrity.api.playintegrity.StandardVerifyRequest
import dev.keiji.deviceintegrity.api.playintegrity.TokenPayloadExternal
import dev.keiji.deviceintegrity.repository.contract.StandardPlayIntegrityTokenRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class StandardPlayIntegrityViewModel @Inject constructor(
    private val standardPlayIntegrityTokenRepository: StandardPlayIntegrityTokenRepository,
    private val playIntegrityTokenVerifyApiClient: PlayIntegrityTokenVerifyApiClient
) : ViewModel() {
    private val _uiState = MutableStateFlow(StandardPlayIntegrityUiState())
    val uiState: StateFlow<StandardPlayIntegrityUiState> = _uiState.asStateFlow()

    fun updateContentBinding(newContent: String) {
        _uiState.update {
            it.copy(contentBinding = newContent)
        }
    }

    fun fetchIntegrityToken() {
        val currentContent = _uiState.value.contentBinding
        // Standard API might allow empty contentBinding for token request,
        // but the calculated property isRequestTokenButtonEnabled handles UI enablement.
        // We proceed with fetching if the button was somehow clicked despite being disabled by UI.

        _uiState.update {
            it.copy(
                isLoading = true,
                status = "Fetching token..."
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
                        status = "Token fetched successfully (Standard API, see Logcat for token)"
                    )
                }
            } catch (e: Exception) {
                Log.e("StandardPlayIntegrityVM", "Error fetching integrity token (Standard)", e)
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        status = "Error (Standard): ${e.message}"
                    )
                }
            }
        }
    }

    fun verifyToken() {
        val token = _uiState.value.integrityToken
        if (token.isBlank()) {
            _uiState.update {
                it.copy(status = "Token not available for verification.")
            }
            return
        }
        _uiState.update {
            it.copy(
                isLoading = true,
                status = "Verifying token..."
            )
        }

        val contentBindingForVerification = _uiState.value.contentBinding // Use the same contentBinding

        viewModelScope.launch {
            try {
                val request = StandardVerifyRequest(token = token, contentBinding = contentBindingForVerification)
                val response = playIntegrityTokenVerifyApiClient.verifyTokenStandard(request)

                Log.d("StandardPlayIntegrityVM", "Verification Response: ${response.tokenPayloadExternal}")

                val verificationStatus = formatTokenPayload(response.tokenPayloadExternal)

                _uiState.update {
                    it.copy(
                        isLoading = false,
                        status = "Server Verification Successful:\n$verificationStatus"
                    )
                }
            } catch (e: Exception) {
                Log.e("StandardPlayIntegrityVM", "Error verifying token with server", e)
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        status = "Error verifying token with server: ${e.message}"
                    )
                }
            }
        }
    }

    private fun formatTokenPayload(payload: TokenPayloadExternal?): String {
        if (payload == null) return "No payload data received."

        val requestDetailsStr = payload.requestDetails?.let { rd ->
            "Request: pkg=${rd.requestPackageName}, nonce='${rd.nonce}', hash='${rd.requestHash}', timestamp=${rd.timestampMillis}"
        } ?: "Request Details: N/A"

        val appIntegrityStr = payload.appIntegrity?.let { ai ->
            "App Integrity: verdict=${ai.appRecognitionVerdict}, pkg=${ai.packageName}, certs=${ai.certificateSha256Digest?.joinToString()?.take(20)}..., versionCode=${ai.versionCode}"
        } ?: "App Integrity: N/A"

        val deviceIntegrityStr = payload.deviceIntegrity?.let { di ->
            "Device Integrity: verdict=${di.deviceRecognitionVerdict?.joinToString()}, attributes=${di.deviceAttributes}, recentActivity=${di.recentDeviceActivity}"
        } ?: "Device Integrity: N/A"

        val accountDetailsStr = payload.accountDetails?.let { ad ->
            "Account Details: licensing=${ad.appLicensingVerdict}"
        } ?: "Account Details: N/A"

        val environmentDetailsStr = payload.environmentDetails?.let { ed ->
            "Environment Details: playProtect=${ed.playProtectVerdict}, appAccessRisk=${ed.appAccessRiskVerdict?.appsDetected?.joinToString()}"
        } ?: "Environment Details: N/A"

        return """
            $requestDetailsStr
            $appIntegrityStr
            $deviceIntegrityStr
            $accountDetailsStr
            $environmentDetailsStr
        """.trimIndent()
    }
}
