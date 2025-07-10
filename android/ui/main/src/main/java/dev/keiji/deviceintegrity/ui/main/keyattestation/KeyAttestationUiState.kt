package dev.keiji.deviceintegrity.ui.main.keyattestation

import dev.keiji.deviceintegrity.repository.contract.KeyPairData
import dev.keiji.deviceintegrity.ui.main.InfoItem
import dev.keiji.deviceintegrity.ui.main.playintegrity.PlayIntegrityProgressConstants

data class KeyAttestationUiState(
    val saltOrNonce: String = "",
    val challenge: String = "",
    val selectedKeyType: CryptoAlgorithm = CryptoAlgorithm.EC, // Default to EC
    val status: String = "", // Keep for general status messages (e.g., "Fetching...", "Failed...")
    val infoItems: List<InfoItem> = emptyList(), // Renamed field for structured results
    val sessionId: String? = null,
    val generatedKeyPairData: KeyPairData? = null,
    val progressValue: Float = PlayIntegrityProgressConstants.NO_PROGRESS,
    val isEcdhAvailable: Boolean = false
) {
    val isSaltOrNonceVisible: Boolean get() = saltOrNonce.isNotEmpty()
    val isChallengeVisible: Boolean get() = challenge.isNotEmpty()

    val isLoading: Boolean
        get() = progressValue != PlayIntegrityProgressConstants.NO_PROGRESS

    // Step 1 is now Key Selection, enabled if not loading
    val isStep1KeySelectionEnabled: Boolean get() = !isLoading

    // Step 2 is Fetch Salt/Nonce/Challenge, enabled if not loading and a key type is selected (always true by default)
    val isStep2FetchSaltOrNonceChallengeEnabled: Boolean get() = !isLoading

    // Step 3 is Generate KeyPair, enabled if not loading, and saltOrNonce and challenge are present
    val isStep3GenerateKeyPairEnabled: Boolean get() = !isLoading && saltOrNonce.isNotEmpty() && challenge.isNotEmpty()

    // Step 4 is Verify Attestation, enabled if not loading and key pair is generated
    val isStep4VerifyAttestationEnabled: Boolean get() = !isLoading && generatedKeyPairData != null
}
