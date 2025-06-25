package dev.keiji.deviceintegrity.ui.main.playintegrity

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.deviceintegrity.api.playintegrity.CreateNonceRequest // Import
import dev.keiji.deviceintegrity.api.playintegrity.PlayIntegrityTokenVerifyApi // Import
import dev.keiji.deviceintegrity.api.playintegrity.VerifyTokenRequest
import dev.keiji.deviceintegrity.repository.contract.PlayIntegrityTokenRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.UUID // Import
import javax.inject.Inject

@HiltViewModel
class ClassicPlayIntegrityViewModel @Inject constructor(
    private val tokenProvider: PlayIntegrityTokenRepository,
    private val playIntegrityTokenVerifyApi: PlayIntegrityTokenVerifyApi // Inject API
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
                        status = "Error fetching nonce: ${e.message}"
                    )
                }
            }
        }
    }

    fun updateNonce(newNonce: String) {
        _uiState.update { it.copy(nonce = newNonce) }
    }

    fun fetchIntegrityToken() {
        val currentNonce = _uiState.value.nonce
        if (currentNonce.isBlank()) {
            _uiState.update {
                it.copy(
                    isLoading = false,
                    status = "Nonce cannot be empty."
                )
            }
            return
        }

        _uiState.update {
            it.copy(
                isLoading = true,
                status = "Fetching token..."
            )
        }
        viewModelScope.launch {
            try {
                val token = tokenProvider.getTokenClassic(currentNonce)
                Log.d("ClassicPlayIntegrityVM", "Integrity Token: $token")
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        integrityToken = token,
                        status = "Token fetched successfully (see Logcat for token)"
                    )
                }
            } catch (e: Exception) {
                Log.e("ClassicPlayIntegrityVM", "Error fetching integrity token", e)
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        status = "Error: ${e.message}"
                    )
                }
            }
        }
    }

    fun verifyToken() {
        val token = _uiState.value.integrityToken
        val nonce = _uiState.value.nonce // Nonce is needed for verification request to server

        if (token.isBlank()) {
            _uiState.update {
                it.copy(status = "Token not available for verification.")
            }
            return
        }
        if (nonce.isBlank()) {
            _uiState.update {
                it.copy(status = "Nonce not available for verification.")
            }
            return
        }

        _uiState.update {
            it.copy(
                isLoading = true,
                status = "Verifying token with server..."
            )
        }

        viewModelScope.launch {
            try {
                // The PlayIntegrityTokenVerifyApi.verifyToken method takes VerifyTokenRequest(token, nonce)
                // This matches the current server implementation which does not require session_id for verification path yet.
                val verifyRequest = VerifyTokenRequest(token = token, nonce = nonce)
                val verifyResponse = playIntegrityTokenVerifyApi.verifyToken(verifyRequest)

                Log.d("ClassicPlayIntegrityVM", "Verification Response: ${verifyResponse.tokenPayloadExternal}")

                // A more descriptive status based on the response
                val appVerdict = verifyResponse.tokenPayloadExternal?.appIntegrity?.appRecognitionVerdict ?: "N/A"
                val deviceVerdict = verifyResponse.tokenPayloadExternal?.deviceIntegrity?.deviceRecognitionVerdict?.joinToString() ?: "N/A"
                val licensingVerdict = verifyResponse.tokenPayloadExternal?.accountDetails?.appLicensingVerdict ?: "N/A"

                val verificationStatus = """
                    Server Verification Successful:
                    App: $appVerdict
                    Device: $deviceVerdict
                    Licensing: $licensingVerdict
                """.trimIndent()

                _uiState.update {
                    it.copy(
                        isLoading = false,
                        status = it.status + "\n" + verificationStatus
                    )
                }
            } catch (e: Exception) {
                Log.e("ClassicPlayIntegrityVM", "Error verifying token with server", e)
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        status = "Error verifying token with server: ${e.message}"
                    )
                }
            }
        }
    }
}
