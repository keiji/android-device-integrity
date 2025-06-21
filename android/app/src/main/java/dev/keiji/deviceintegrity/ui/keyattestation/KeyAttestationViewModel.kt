package dev.keiji.deviceintegrity.ui.keyattestation

import androidx.lifecycle.ViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

class KeyAttestationViewModel : ViewModel() {
    private val _uiState = MutableStateFlow(KeyAttestationUiState())
    val uiState: StateFlow<KeyAttestationUiState> = _uiState.asStateFlow()

    // TODO: Implement logic to interact with Key Attestation API
}
