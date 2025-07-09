package dev.keiji.deviceintegrity.ui.main.keyattestation

import dev.keiji.deviceintegrity.repository.contract.KeyPairData

data class AttestationInfoItem(
    val label: String,
    val value: String,
    val isHeader: Boolean = false,
    val indentLevel: Int = 0
)

data class KeyAttestationUiState(
    val nonce: String = "",
    val challenge: String = "",
    val selectedKeyType: CryptoAlgorithm = CryptoAlgorithm.EC, // Default to EC
    val status: String = "", // Keep for general status messages (e.g., "Fetching...", "Failed...")
    val verificationResultItems: List<AttestationInfoItem> = emptyList(), // New field for structured results
    val sessionId: String? = null,
    val generatedKeyPairData: KeyPairData? = null
    // deviceInfoText and securityInfoText are removed as their content will be part of verificationResultItems
) {
    val isNonceVisible: Boolean get() = nonce.isNotEmpty()
    val isChallengeVisible: Boolean get() = challenge.isNotEmpty()

    val isStep2KeySelectionEnabled: Boolean get() = nonce.isNotEmpty() && challenge.isNotEmpty()
    val isStep3GenerateKeyPairEnabled: Boolean get() = isStep2KeySelectionEnabled
    val isStep4VerifyAttestationEnabled: Boolean get() = generatedKeyPairData != null
}
