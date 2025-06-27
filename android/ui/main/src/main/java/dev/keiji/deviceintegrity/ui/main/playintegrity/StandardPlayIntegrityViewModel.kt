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
                        status = "Token fetched successfully (Standard API, see Logcat for token)",
                        errorMessages = emptyList()
                    )
                }
            } catch (e: Exception) {
                Log.e("StandardPlayIntegrityVM", "Error fetching integrity token (Standard)", e)
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        status = "Error fetching integrity token (Standard).",
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
                status = "Verifying token...",
                errorMessages = emptyList(),
                standardVerifyResponse = null
            )
        }

        val contentBindingForVerification = _uiState.value.contentBinding

        viewModelScope.launch {
            try {
                val request = StandardVerifyRequest(token = token, nonce = contentBindingForVerification)
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
