package dev.keiji.deviceintegrity.ui.main.playintegrity

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.deviceintegrity.api.playintegrity.CreateNonceRequest // Import
import dev.keiji.deviceintegrity.api.playintegrity.PlayIntegrityTokenVerifyApiClient // Import
import dev.keiji.deviceintegrity.api.playintegrity.VerifyTokenRequest
import dev.keiji.deviceintegrity.repository.contract.ClassicPlayIntegrityTokenRepository
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
    private val playIntegrityTokenVerifyApi: PlayIntegrityTokenVerifyApiClient // Inject API
) : ViewModel() {
    private val _uiState = MutableStateFlow(ClassicPlayIntegrityUiState())
    val uiState: StateFlow<ClassicPlayIntegrityUiState> = _uiState.asStateFlow()

    // Session ID for this ViewModel instance
    private val sessionId: String = UUID.randomUUID().toString()

    fun fetchNonce() {
        _uiState.update {
            it.copy(
                isLoading = true,
                status = "Fetching nonce from server..."
            )
        }
        viewModelScope.launch {
            try {
                val request = CreateNonceRequest(sessionId = sessionId)
                val response = playIntegrityTokenVerifyApi.getNonce(request)
                _uiState.update {
                    it.copy(
                        nonce = response.nonce,
                        isLoading = false,
                        status = "Nonce fetched: ${response.nonce}"
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
                status = "Verifying token with server...",
                errorMessages = emptyList(),
                verifyTokenResponse = null
            )
        }

        viewModelScope.launch {
            try {
                val verifyRequest = VerifyTokenRequest(token = token, sessionId = sessionId)
                val verifyResponse = playIntegrityTokenVerifyApi.verifyToken(verifyRequest)

                Log.d("ClassicPlayIntegrityVM", "Verification Response: ${verifyResponse.tokenPayloadExternal}")

                _uiState.update {
                    it.copy(
                        isLoading = false,
                        status = "Token verification complete.",
                        verifyTokenResponse = verifyResponse,
                        errorMessages = emptyList()
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
