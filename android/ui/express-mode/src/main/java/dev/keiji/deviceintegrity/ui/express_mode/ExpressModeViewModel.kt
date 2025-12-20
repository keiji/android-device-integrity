package dev.keiji.deviceintegrity.ui.express_mode

import androidx.lifecycle.ViewModel
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject

@HiltViewModel
class ExpressModeViewModel @Inject constructor() : ViewModel() {

    private val _uiState = MutableStateFlow(
        ExpressModeUiState(
            progress = 3,
            maxProgress = 5,
            resultInfoItems = emptyList(),
            status = "",
        )
    )
    val uiState: StateFlow<ExpressModeUiState> = _uiState.asStateFlow()

    private val _uiEvent = MutableStateFlow<ExpressModeUiEvent?>(null)
    val uiEvent: StateFlow<ExpressModeUiEvent?> = _uiEvent.asStateFlow()
}
