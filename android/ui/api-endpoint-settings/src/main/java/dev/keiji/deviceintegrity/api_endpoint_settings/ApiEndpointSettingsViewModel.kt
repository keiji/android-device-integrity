package dev.keiji.deviceintegrity.api_endpoint_settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.deviceintegrity.repository.contract.PreferencesRepository
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class ApiEndpointSettingsViewModel @Inject constructor(
    private val preferencesRepository: PreferencesRepository
) : ViewModel() {

    val apiEndpointUrl: StateFlow<String?> = preferencesRepository.apiEndpointUrl
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = null // Or some initial loading state
        )

    fun saveApiEndpointUrl(url: String) {
        viewModelScope.launch {
            preferencesRepository.saveApiEndpointUrl(url)
        }
    }
}
