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
        _uiState.update { it.copy(contentBinding = newContent) }
    }

    fun fetchIntegrityToken() {
        val currentContent = _uiState.value.contentBinding
        // Standard API might allow empty contentBinding, so we don't check for isBlank here
        // unless specific requirements state otherwise.

        _uiState.update { it.copy(isLoading = true, result = "") }
        viewModelScope.launch {
            try {
                // Pass a dummy cloudProjectNumber (e.g., 0L) as it's managed by the provider.
                // Pass currentContent as the requestHash.
                val token = tokenProvider.getTokenStandard(
                    cloudProjectNumber = 0L, // Dummy value, managed by provider
                    requestHash = currentContent
                )
                Log.d("StandardPlayIntegrityVM", "Integrity Token (Standard): $token")
                _uiState.update {
                    it.copy(isLoading = false, result = "Token fetched successfully (Standard API, see Logcat for token)")
                }
            } catch (e: Exception) {
                Log.e("StandardPlayIntegrityVM", "Error fetching integrity token (Standard)", e)
                _uiState.update { it.copy(isLoading = false, result = "Error (Standard): ${e.message}") }
            }
        }
    }
}
