package dev.keiji.deviceintegrity.ui.main.playintegrity

import androidx.lifecycle.ViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

class PlayIntegrityViewModel : ViewModel() {
    private val _uiState = MutableStateFlow(PlayIntegrityUiState())
    val uiState: StateFlow<PlayIntegrityUiState> = _uiState.asStateFlow()

    // TODO: Implement logic to interact with Play Integrity API
}
