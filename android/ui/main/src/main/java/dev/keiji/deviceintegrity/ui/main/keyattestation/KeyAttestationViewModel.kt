package dev.keiji.deviceintegrity.ui.main.keyattestation

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch // Ensure this is imported

// Removed KeyAttestationUiEvent and Channel as status is now part of UiState.
// If one-time events are needed later, they can be re-added.

class KeyAttestationViewModel : ViewModel() {

    private val _uiState = MutableStateFlow(KeyAttestationUiState())
    val uiState: StateFlow<KeyAttestationUiState> = _uiState.asStateFlow()

    // Event handler for Nonce change
    fun onNonceChange(newNonce: String) {
        _uiState.update { it.copy(nonce = newNonce) }
    }

    // Event handler for Challenge change
    fun onChallengeChange(newChallenge: String) {
        _uiState.update { it.copy(challenge = newChallenge) }
    }

    // Event handler for Selected Key Type change
    fun onSelectedKeyTypeChange(newKeyType: String) {
        _uiState.update { it.copy(selectedKeyType = newKeyType) }
    }

    // Action to fetch Nonce/Challenge
    fun fetchNonceChallenge() {
        viewModelScope.launch {
            _uiState.update { it.copy(status = "Fetching Nonce/Challenge...") }
            // Simulate network call or actual logic
            kotlinx.coroutines.delay(1000) // Simulate delay
            _uiState.update {
                it.copy(
                    nonce = "SAMPLE_NONCE_FROM_SERVER_123",
                    challenge = "SAMPLE_CHALLENGE_FROM_SERVER_ABC",
                    status = "Nonce/Challenge fetched."
                )
            }
        }
    }

    // Action to generate KeyPair
    fun generateKeyPair() {
        viewModelScope.launch {
            _uiState.update { it.copy(status = "Generating KeyPair...") }
            // Simulate key generation
            kotlinx.coroutines.delay(1000) // Simulate delay
            _uiState.update { it.copy(status = "KeyPair Generated.") }
        }
    }

    // Action to request verification of KeyAttestation
    fun requestVerifyKeyAttestation() {
        viewModelScope.launch {
            _uiState.update { it.copy(status = "Verifying KeyAttestation...") }
            // Simulate verification
            kotlinx.coroutines.delay(1500) // Simulate delay
            // Simulate success/failure
            val success = kotlin.random.Random.nextBoolean()
            if (success) {
                _uiState.update { it.copy(status = "Verification Complete.") }
            } else {
                _uiState.update { it.copy(status = "Verification Failed.") }
            }
        }
    }

    // Hex utility functions can be kept if they are planned for use later,
    // but are not strictly necessary for the current placeholder logic.
    // private fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }.uppercase()
    // private fun String.decodeHex(): ByteArray {
    //     check(length % 2 == 0) { "Must have an even length" }
    //     return chunked(2)
    //         .map { it.toInt(16).toByte() }
    //         .toByteArray()
    // }
}
