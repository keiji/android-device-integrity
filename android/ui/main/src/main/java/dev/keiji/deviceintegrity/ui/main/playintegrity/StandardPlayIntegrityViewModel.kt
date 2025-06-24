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
class StandardPlayIntegrityViewModel @Inject constructor(
    private val tokenProvider: PlayIntegrityTokenRepository
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
                val token = tokenProvider.getTokenStandard(
                    cloudProjectNumber = 0L, // Dummy value, managed by provider
                    requestHash = currentContent
                )
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
        // TODO: Implement token verification logic (async)
        viewModelScope.launch {
            kotlinx.coroutines.delay(1000) // Simulate network call
            Log.d("StandardPlayIntegrityVM", "verifyToken() called. Token: $token")
            _uiState.update {
                it.copy(
                    isLoading = false,
                    status = it.status + "\nVerification requested (Not yet implemented)."
                )
            }
        }
    }
}
