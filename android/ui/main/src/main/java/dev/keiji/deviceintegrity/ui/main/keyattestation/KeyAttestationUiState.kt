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
    val generatedKeyPairData: KeyPairData? = null,
    val deviceInfoText: String = "",
    val securityInfoText: String = ""
)
