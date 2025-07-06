package dev.keiji.deviceintegrity.ui.main.keyattestation

import dev.keiji.deviceintegrity.repository.contract.KeyPairData

data class KeyAttestationUiState(
    val nonce: String = "",
    val challenge: String = "",
    val selectedKeyType: CryptoAlgorithm = CryptoAlgorithm.EC, // Default to EC
    val status: String = "",
    val sessionId: String? = null,
    val generatedKeyPairData: KeyPairData? = null
)
