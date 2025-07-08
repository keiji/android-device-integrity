package dev.keiji.deviceintegrity.ui.main.keyattestation

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.deviceintegrity.api.keyattestation.KeyAttestationVerifyApiClient
import dev.keiji.deviceintegrity.api.keyattestation.PrepareRequest
import dev.keiji.deviceintegrity.api.keyattestation.VerifyEcRequest
import dev.keiji.deviceintegrity.crypto.contract.Signer
import dev.keiji.deviceintegrity.crypto.contract.qualifier.EC
import dev.keiji.deviceintegrity.repository.contract.KeyPairRepository
import dev.keiji.deviceintegrity.ui.main.util.Base64Utils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import java.util.UUID
import javax.inject.Inject
import kotlin.io.encoding.Base64

@HiltViewModel
class KeyAttestationViewModel @Inject constructor(
    private val keyPairRepository: KeyPairRepository,
    private val keyAttestationVerifyApiClient: KeyAttestationVerifyApiClient,
    @EC private val signer: Signer
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
    fun onSelectedKeyTypeChange(newKeyType: CryptoAlgorithm) {
        _uiState.update { it.copy(selectedKeyType = newKeyType) }
    }

    // Action to fetch Nonce/Challenge
    fun fetchNonceChallenge() {
        viewModelScope.launch {
            _uiState.update {
                it.copy(
                    status = "Fetching Nonce/Challenge...",
                    nonce = "",
                    challenge = ""
                )
            }
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
            _uiState.update {
                it.copy(
                    status = "Generating KeyPair...",
                    generatedKeyPairData = null
                )
            }

            val currentChallenge = uiState.value.challenge
            if (currentChallenge.isEmpty()) {
                _uiState.update { it.copy(status = "Challenge is not available. Fetch Nonce/Challenge first.") }
                return@launch
            }

            try {
                // Decode the challenge from Base64Url
                // Using UrlSafeNoPadding to ensure no padding is used/expected.
                val decodedChallenge = withContext(Dispatchers.Default) {
                    Base64Utils.UrlSafeNoPadding.decode(currentChallenge)
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
            val keyPair = currentKeyPairData?.keyPair
            if (keyPair == null) {
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
                    // Using UrlSafeNoPadding to ensure no padding is used/expected.
                    val decodedServerNonce = Base64Utils.UrlSafeNoPadding.decode(serverNonceB64Url)
                    val dataToSign = decodedServerNonce + nonceB

                    // 2. Signing
                    val privateKey = keyPair.private
                    val signatureData = signer.sign(dataToSign, privateKey)

                    // 3. Encoding for Request (Base64URL, without padding using Base64Utils)
                    val signatureDataBase64UrlEncoded = Base64Utils.UrlSafeNoPadding.encode(signatureData)
                    val nonceBBase64UrlEncoded = Base64Utils.UrlSafeNoPadding.encode(nonceB)
                    val certificateChainBase64Encoded =
                        currentKeyPairData.certificates.map { cert ->
                            Base64.Default.encode(cert.encoded)
                        }

                    // 4. API Call
                    val request = VerifyEcRequest(
                        sessionId = currentSessionId,
                        signatureDataBase64UrlEncoded = signatureDataBase64UrlEncoded,
                        nonceBBase64UrlEncoded = nonceBBase64UrlEncoded,
                        certificateChainBase64Encoded = certificateChainBase64Encoded
                    )
                    keyAttestationVerifyApiClient.verifyEc(request)
                }

                if (response.isVerified) {
                    val statusBuilder = StringBuilder()
                    statusBuilder.appendLine("Verification successful.")
                    statusBuilder.appendLine("Session ID: ${response.sessionId}")
                    statusBuilder.appendLine("Is Verified: ${response.isVerified}")
                    statusBuilder.appendLine("Attestation Security Level: ${response.attestationSecurityLevel}")
                    statusBuilder.appendLine("Attestation Version: ${response.attestationVersion}")
                    statusBuilder.appendLine("KeyMint Security Level: ${response.keymintSecurityLevel}")
                    statusBuilder.appendLine("KeyMint Version: ${response.keymintVersion}")
                    statusBuilder.appendLine("Reason: ${response.reason ?: "N/A"}")

                    statusBuilder.appendLine("\nSoftware Enforced Properties:")
                    response.softwareEnforcedProperties?.let { props ->
                        statusBuilder.appendLine("  Attestation Application ID:")
                        props.attestationApplicationId?.let { appId ->
                            statusBuilder.appendLine("    Application Signature: ${appId.applicationSignature ?: "N/A"}")
                            statusBuilder.appendLine("    Attestation Application ID: ${appId.attestationApplicationId ?: "N/A"}")
                            statusBuilder.appendLine("    Attestation Application Version Code: ${appId.attestationApplicationVersionCode ?: "N/A"}")
                        } ?: statusBuilder.appendLine("    N/A")
                        statusBuilder.appendLine("  Creation Datetime: ${props.creationDatetime ?: "N/A"}")
                        statusBuilder.appendLine("  Algorithm: ${props.algorithm ?: "N/A"}")
                        statusBuilder.appendLine("  Boot Patch Level: ${props.bootPatchLevel ?: "N/A"}")
                        statusBuilder.appendLine("  Digests: ${props.digests?.joinToString() ?: "N/A"}")
                        statusBuilder.appendLine("  EC Curve: ${props.ecCurve ?: "N/A"}")
                        statusBuilder.appendLine("  Key Size: ${props.keySize ?: "N/A"}")
                        statusBuilder.appendLine("  No Auth Required: ${props.noAuthRequired ?: "N/A"}")
                        statusBuilder.appendLine("  Origin: ${props.origin ?: "N/A"}")
                        statusBuilder.appendLine("  OS Patch Level: ${props.osPatchLevel ?: "N/A"}")
                        statusBuilder.appendLine("  OS Version: ${props.osVersion ?: "N/A"}")
                        statusBuilder.appendLine("  Purpose: ${props.purpose?.joinToString() ?: "N/A"}")
                        props.rootOfTrust?.let { rot ->
                            statusBuilder.appendLine("  Root of Trust:")
                            statusBuilder.appendLine("    Device Locked: ${rot.deviceLocked ?: "N/A"}")
                            statusBuilder.appendLine("    Verified Boot Hash: ${rot.verifiedBootHash ?: "N/A"}")
                            statusBuilder.appendLine("    Verified Boot Key: ${rot.verifiedBootKey ?: "N/A"}")
                            statusBuilder.appendLine("    Verified Boot State: ${rot.verifiedBootState ?: "N/A"}")
                        } ?: statusBuilder.appendLine("  Root of Trust: N/A")
                        statusBuilder.appendLine("  Vendor Patch Level: ${props.vendorPatchLevel ?: "N/A"}")
                    } ?: statusBuilder.appendLine("  N/A")

                    statusBuilder.appendLine("\nTEE Enforced Properties:")
                    response.teeEnforcedProperties?.let { props ->
                        statusBuilder.appendLine("  Attestation Application ID:")
                        props.attestationApplicationId?.let { appId ->
                            statusBuilder.appendLine("    Application Signature: ${appId.applicationSignature ?: "N/A"}")
                            statusBuilder.appendLine("    Attestation Application ID: ${appId.attestationApplicationId ?: "N/A"}")
                            statusBuilder.appendLine("    Attestation Application Version Code: ${appId.attestationApplicationVersionCode ?: "N/A"}")
                        } ?: statusBuilder.appendLine("    N/A")
                        statusBuilder.appendLine("  Creation Datetime: ${props.creationDatetime ?: "N/A"}")
                        statusBuilder.appendLine("  Algorithm: ${props.algorithm ?: "N/A"}")
                        statusBuilder.appendLine("  Boot Patch Level: ${props.bootPatchLevel ?: "N/A"}")
                        statusBuilder.appendLine("  Digests: ${props.digests?.joinToString() ?: "N/A"}")
                        statusBuilder.appendLine("  EC Curve: ${props.ecCurve ?: "N/A"}")
                        statusBuilder.appendLine("  Key Size: ${props.keySize ?: "N/A"}")
                        statusBuilder.appendLine("  No Auth Required: ${props.noAuthRequired ?: "N/A"}")
                        statusBuilder.appendLine("  Origin: ${props.origin ?: "N/A"}")
                        statusBuilder.appendLine("  OS Patch Level: ${props.osPatchLevel ?: "N/A"}")
                        statusBuilder.appendLine("  OS Version: ${props.osVersion ?: "N/A"}")
                        statusBuilder.appendLine("  Purpose: ${props.purpose?.joinToString() ?: "N/A"}")
                        props.rootOfTrust?.let { rot ->
                            statusBuilder.appendLine("  Root of Trust:")
                            statusBuilder.appendLine("    Device Locked: ${rot.deviceLocked ?: "N/A"}")
                            statusBuilder.appendLine("    Verified Boot Hash: ${rot.verifiedBootHash ?: "N/A"}")
                            statusBuilder.appendLine("    Verified Boot Key: ${rot.verifiedBootKey ?: "N/A"}")
                            statusBuilder.appendLine("    Verified Boot State: ${rot.verifiedBootState ?: "N/A"}")
                        } ?: statusBuilder.appendLine("  Root of Trust: N/A")
                        statusBuilder.appendLine("  Vendor Patch Level: ${props.vendorPatchLevel ?: "N/A"}")
                    } ?: statusBuilder.appendLine("  N/A")

                    _uiState.update {
                        it.copy(status = statusBuilder.toString())
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
