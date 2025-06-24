package dev.keiji.deviceintegrity.ui.main.playintegrity

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.deviceintegrity.repository.contract.PlayIntegrityTokenRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class ClassicPlayIntegrityViewModel @Inject constructor(
    private val tokenProvider: PlayIntegrityTokenRepository
) : ViewModel() {
    private val _uiState = MutableStateFlow(ClassicPlayIntegrityUiState())
    val uiState: StateFlow<ClassicPlayIntegrityUiState> = _uiState.asStateFlow()

    fun fetchNonce() {
        // Simulate fetching nonce
        val newNonce = "fetched-nonce-${System.currentTimeMillis()}"
        _uiState.update {
            it.copy(
                nonce = newNonce,
                isLoading = false, // Assuming nonce fetching is quick or UI updates after
                status = "Nonce fetched: $newNonce"
            )
        }
    }

    // This function might not be strictly needed if nonce is only fetched, not manually updated.
    // Kept for potential future use or if direct nonce input is re-enabled.
    fun updateNonce(newNonce: String) {
        _uiState.update { it.copy(nonce = newNonce) }
    }

    fun fetchIntegrityToken() {
        val currentNonce = _uiState.value.nonce
        if (currentNonce.isBlank()) {
            _uiState.update {
                it.copy(
                    isLoading = false, // Ensure isLoading is false if we return early
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
        // TODO: Implement token verification logic (async)
        // For now, simulate a delay and result
        viewModelScope.launch {
            kotlinx.coroutines.delay(1000) // Simulate network call
            Log.d("ClassicPlayIntegrityVM", "verifyToken() called. Token: $token")
            _uiState.update {
                it.copy(
                    isLoading = false,
                    status = it.status + "\nVerification requested (Not yet implemented)."
                )
            }
        }
    }
}
