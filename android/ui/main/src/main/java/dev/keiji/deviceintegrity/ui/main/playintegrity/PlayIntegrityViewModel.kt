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
class PlayIntegrityViewModel @Inject constructor(
    private val tokenProvider: PlayIntegrityTokenRepository
) : ViewModel() {
    private val _uiState = MutableStateFlow(PlayIntegrityUiState())
    val uiState: StateFlow<PlayIntegrityUiState> = _uiState.asStateFlow()

    fun updateNonce(newNonce: String) {
        _uiState.update { it.copy(nonce = newNonce) }
    }

    fun fetchIntegrityToken() {
        val currentNonce = _uiState.value.nonce
        if (currentNonce.isBlank()) {
            _uiState.update { it.copy(isLoading = false, result = "Nonce cannot be empty.") }
            return
        }

        _uiState.update { it.copy(isLoading = true, result = "") }
        viewModelScope.launch {
            try {
                val token = tokenProvider.getTokenClassic(currentNonce)
                Log.d("PlayIntegrityViewModel", "Integrity Token: $token")
                _uiState.update {
                    it.copy(isLoading = false, result = "Token fetched successfully (see Logcat for token)")
                    // For security reasons, do not display the raw token in the UI in a real app.
                    // This is just for testing. A real app would send it to a backend server.
                }
            } catch (e: Exception) {
                Log.e("PlayIntegrityViewModel", "Error fetching integrity token", e)
                _uiState.update { it.copy(isLoading = false, result = "Error: ${e.message}") }
            }
        }
    }
}
