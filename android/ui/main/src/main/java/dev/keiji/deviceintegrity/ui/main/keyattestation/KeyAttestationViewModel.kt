package dev.keiji.deviceintegrity.ui.main.keyattestation

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.security.SecureRandom
import dev.keiji.deviceintegrity.domain.model.CryptoAlgorithm

sealed interface KeyAttestationUiEvent {
    data class ShowToast(val message: String) : KeyAttestationUiEvent
}

class KeyAttestationViewModel : ViewModel() {
    val availableAlgorithms: List<CryptoAlgorithm> = CryptoAlgorithm.values().toList()

    companion object {
        private const val MAX_NONCE_LENGTH_BYTES = 32
        private const val DEFAULT_NONCE_LENGTH_BYTES = 16 // Initial nonce length
    }

    private val _uiState = MutableStateFlow(KeyAttestationUiState())
    val uiState: StateFlow<KeyAttestationUiState> = _uiState.asStateFlow()

    private val _eventChannel = Channel<KeyAttestationUiEvent>()
    val eventFlow = _eventChannel.receiveAsFlow()

    private var nonceByteArray: ByteArray = ByteArray(0)

    init {
        generateInitialNonce()
    }

    private fun generateInitialNonce() {
        val random = SecureRandom()
        val newNonce = ByteArray(DEFAULT_NONCE_LENGTH_BYTES)
        random.nextBytes(newNonce)
        nonceByteArray = newNonce
        _uiState.update { it.copy(nonce = newNonce.toHexString()) }
    }

    fun updateNonce(newNonceHex: String) {
        val filteredNonce = newNonceHex.filter { it.isLetterOrDigit() }.uppercase()
        if (filteredNonce.length > MAX_NONCE_LENGTH_BYTES * 2) {
            // Prevent exceeding max length
            return
        }

        // Validate hex string
        if (!filteredNonce.matches(Regex("^[0-9A-F]*$"))) {
            // Or send an event to show an error
            return
        }

        _uiState.update { it.copy(nonce = filteredNonce) }
        if (filteredNonce.length % 2 == 0) { // Check if length is even
            nonceByteArray = filteredNonce.decodeHex()
        } else {
            // Handle odd length string, e.g., clear nonceByteArray or keep previous valid value
            // For now, let's clear it or assign an empty array if it's invalid for submission
            nonceByteArray = ByteArray(0) // Or handle as an invalid state
        }
    }

    fun submit() {
        viewModelScope.launch {
            // TODO: Implement actual key attestation logic using nonceByteArray
            _eventChannel.send(KeyAttestationUiEvent.ShowToast("ボタンが押されました"))
        }
    }

    // Helper extension functions
    private fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }.uppercase()
    private fun String.decodeHex(): ByteArray {
        check(length % 2 == 0) { "Must have an even length" }
        return chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }
}
