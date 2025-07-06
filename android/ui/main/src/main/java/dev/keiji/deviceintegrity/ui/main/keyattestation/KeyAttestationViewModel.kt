package dev.keiji.deviceintegrity.ui.main.keyattestation

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.deviceintegrity.api.keyattestation.KeyAttestationRequest
import dev.keiji.deviceintegrity.api.keyattestation.KeyAttestationVerifyApiClient
import dev.keiji.deviceintegrity.util.Base64UrlEncoder
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.security.SecureRandom
import javax.inject.Inject

sealed interface KeyAttestationUiEvent {
    data class ShowToast(val message: String) : KeyAttestationUiEvent
}

@HiltViewModel
class KeyAttestationViewModel @Inject constructor(
    private val keyAttestationVerifyApiClient: KeyAttestationVerifyApiClient
) : ViewModel() {
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
        _uiState.update { it.copy(nonce = newNonce.toHexString(), attestationResult = null) }
    }

    fun updateNonce(newNonceHex: String) {
        val filteredNonce = newNonceHex.filter { it.isLetterOrDigit() }.uppercase()
        if (filteredNonce.length > MAX_NONCE_LENGTH_BYTES * 2) {
            _uiState.update { it.copy(isNonceValid = false) }
            viewModelScope.launch { _eventChannel.send(KeyAttestationUiEvent.ShowToast("Nonce is too long.")) }
            return
        }

        if (!filteredNonce.matches(Regex("^[0-9A-F]*$"))) {
            _uiState.update { it.copy(isNonceValid = false) }
            viewModelScope.launch { _eventChannel.send(KeyAttestationUiEvent.ShowToast("Nonce contains invalid characters.")) }
            return
        }

        if (filteredNonce.length % 2 != 0) {
             _uiState.update { it.copy(isNonceValid = false, nonce = filteredNonce) }
             // Don't clear nonceByteArray, allow user to continue typing
            return
        }

        _uiState.update { it.copy(nonce = filteredNonce, isNonceValid = true) }
        nonceByteArray = filteredNonce.decodeHex()
    }

    fun submit() {
        if (nonceByteArray.isEmpty()) {
            viewModelScope.launch {
                _eventChannel.send(KeyAttestationUiEvent.ShowToast("Nonce is empty or invalid."))
            }
            return
        }

        _uiState.update { it.copy(isLoading = true, attestationResult = null) }

        viewModelScope.launch {
            try {
                val challenge = Base64UrlEncoder.encodeNoPadding(nonceByteArray)

                // TODO: The attestationStatement needs a real source.
                // For now, using a placeholder. This is a known limitation.
                val attestationStatementPlaceholder = "DUMMY_ATTESTATION_STATEMENT"

                val request = KeyAttestationRequest(
                    attestationStatement = attestationStatementPlaceholder,
                    challenge = challenge
                )

                val response = keyAttestationVerifyApiClient.verifyAttestation(request)

                _uiState.update {
                    it.copy(
                        isLoading = false,
                        attestationResult = "Valid: ${response.isValid}, Errors: ${response.errorMessages?.joinToString() ?: "None"}"
                    )
                }
                _eventChannel.send(KeyAttestationUiEvent.ShowToast("Attestation check completed."))

            } catch (e: Exception) {
                // Log.e("KeyAttestationViewModel", "Attestation failed", e) // Proper logging
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        attestationResult = "Error: ${e.message}"
                    )
                }
                _eventChannel.send(KeyAttestationUiEvent.ShowToast("Attestation failed: ${e.message}"))
            }
        }
    }

    private fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }.uppercase()
    private fun String.decodeHex(): ByteArray {
        // Already validated for even length and hex characters in updateNonce
        return chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }
}
