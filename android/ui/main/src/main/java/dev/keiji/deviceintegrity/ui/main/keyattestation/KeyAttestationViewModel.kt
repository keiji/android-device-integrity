package dev.keiji.deviceintegrity.ui.main.keyattestation

import android.util.Base64
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.keiji.deviceintegrity.api.keyattestation.KeyAttestationVerifyApiClient
import dev.keiji.deviceintegrity.api.keyattestation.PrepareRequest
import dev.keiji.deviceintegrity.api.keyattestation.VerifyEcRequest
import dev.keiji.deviceintegrity.crypto.contract.Signer
import dev.keiji.deviceintegrity.repository.contract.KeyPairRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch // Ensure this is imported
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import java.util.UUID

class KeyAttestationViewModel(
    private val keyPairRepository: KeyPairRepository,
    private val keyAttestationVerifyApiClient: KeyAttestationVerifyApiClient,
    private val signer: Signer
) : ViewModel() {

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
            _uiState.update { it.copy(status = "Fetching Nonce/Challenge...", nonce = "", challenge = "") }
            try {
                val newSessionId = UUID.randomUUID().toString()
                _uiState.update { it.copy(sessionId = newSessionId) }

                val request = PrepareRequest(sessionId = newSessionId)

                // Perform network call on IO dispatcher
                val response = withContext(Dispatchers.IO) {
                    keyAttestationVerifyApiClient.prepare(request)
                }

                _uiState.update {
                    it.copy(
                        nonce = response.nonceBase64UrlEncoded,
                        challenge = response.challengeBase64UrlEncoded,
                        status = "Nonce/Challenge fetched successfully."
                    )
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        status = "Failed to fetch Nonce/Challenge: ${e.message}",
                        sessionId = null // Clear sessionId on failure
                    )
                }
                // Optionally log the exception e.g. Timber.e(e, "fetchNonceChallenge failed")
            }
        }
    }

    // Action to generate KeyPair
    fun generateKeyPair() {
        viewModelScope.launch {
            _uiState.update { it.copy(status = "Generating KeyPair...", generatedKeyPairData = null) }

            val currentChallenge = uiState.value.challenge
            if (currentChallenge.isEmpty()) {
                _uiState.update { it.copy(status = "Challenge is not available. Fetch Nonce/Challenge first.") }
                return@launch
            }

            try {
                // Decode the challenge from Base64Url
                // Using NO_WRAP as KeyGenParameterSpec.Builder#setAttestationChallenge expects the raw challenge bytes.
                // URL_SAFE is used because the server sends it as Base64UrlEncoded.
                val decodedChallenge = withContext(Dispatchers.Default) {
                    Base64.decode(currentChallenge, Base64.URL_SAFE or Base64.NO_WRAP)
                }

                // Perform key generation on IO dispatcher
                val keyPairDataResult = withContext(Dispatchers.IO) {
                    keyPairRepository.generateKeyPair(decodedChallenge)
                }

                _uiState.update {
                    it.copy(
                        generatedKeyPairData = keyPairDataResult,
                        status = "KeyPair generated successfully. Alias: ${keyPairDataResult.keyAlias}"
                    )
                }
            } catch (e: Exception) {
                _uiState.update { it.copy(status = "Failed to generate KeyPair: ${e.message}") }
                // Optionally log the exception
            }
        }
    }

    // Action to request verification of KeyAttestation
    fun requestVerifyKeyAttestation() {
        viewModelScope.launch {
            _uiState.update { it.copy(status = "Verifying KeyAttestation...") }

            val currentSessionId = uiState.value.sessionId
            val currentKeyPairData = uiState.value.generatedKeyPairData
            val serverNonceB64Url = uiState.value.nonce // This is server's nonce from prepare step

            if (currentSessionId == null) {
                _uiState.update { it.copy(status = "SessionId is missing. Fetch Nonce/Challenge first.") }
                return@launch
            }
            if (currentKeyPairData?.keyPair == null) {
                _uiState.update { it.copy(status = "KeyPair is not generated yet.") }
                return@launch
            }
            if (serverNonceB64Url.isEmpty()) {
                _uiState.update { it.copy(status = "Server Nonce is missing. Fetch Nonce/Challenge first.") }
                return@launch
            }

            try {
                // Perform encoding, signing, and network call on appropriate dispatchers
                val response = withContext(Dispatchers.IO) {
                    // 1. Nonce Handling
                    val nonceB = ByteArray(32)
                    SecureRandom().nextBytes(nonceB)

                    // Server nonce is Base64URL Encoded
                    val decodedServerNonce = Base64.decode(serverNonceB64Url, Base64.URL_SAFE or Base64.NO_WRAP)
                    val dataToSign = decodedServerNonce + nonceB

                    // 2. Signing
                    val privateKey = currentKeyPairData.keyPair.private
                    val signatureData = signer.sign(dataToSign, privateKey)

                    // 3. Encoding for Request (Base64URL as per task)
                    val base64Flags = Base64.URL_SAFE or Base64.NO_WRAP
                    val signedDataBase64UrlEncoded = Base64.encodeToString(signatureData, base64Flags)
                    val nonceBBase64UrlEncoded = Base64.encodeToString(nonceB, base64Flags)
                    val certificateChainBase64UrlEncoded = currentKeyPairData.certificates.map { cert ->
                        Base64.encodeToString(cert.encoded, base64Flags)
                    }

                    // 4. API Call
                    val request = VerifyEcRequest(
                        sessionId = currentSessionId,
                        signedDataBase64Encoded = signedDataBase64UrlEncoded, // Field name is Base64Encoded, but task requires UrlEncoded
                        nonceBBase64Encoded = nonceBBase64UrlEncoded, // Field name is Base64Encoded, but task requires UrlEncoded
                        certificateChainBase64Encoded = certificateChainBase64UrlEncoded // Field name is Base64Encoded, but task requires UrlEncoded
                    )
                    keyAttestationVerifyApiClient.verifyEc(request)
                }

                if (response.isVerified) {
                    _uiState.update {
                        it.copy(status = "Verification successful. Session: ${response.sessionId}, Verified: ${response.isVerified}")
                    }
                } else {
                    _uiState.update {
                        it.copy(status = "Verification failed. Reason: ${response.reason ?: "Unknown"}")
                    }
                }

            } catch (e: Exception) {
                _uiState.update { it.copy(status = "Failed to verify KeyAttestation: ${e.message}") }
                // Optionally log the exception
            }
        }
    }
}
