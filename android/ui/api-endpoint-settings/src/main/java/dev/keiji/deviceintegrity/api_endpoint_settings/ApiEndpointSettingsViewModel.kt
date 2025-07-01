package dev.keiji.deviceintegrity.api_endpoint_settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.deviceintegrity.api_endpoint_settings.validation.ValidationConstants
import dev.keiji.deviceintegrity.repository.contract.PreferencesRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.net.MalformedURLException
import java.net.URL
import javax.inject.Inject

@HiltViewModel
class ApiEndpointSettingsViewModel @Inject constructor(
    private val preferencesRepository: PreferencesRepository
) : ViewModel() {

    private val _uiState = MutableStateFlow(ApiEndpointSettingsUiState())
    val uiState: StateFlow<ApiEndpointSettingsUiState> = _uiState.asStateFlow()

    init {
        _uiState.update { it.copy(isLoading = false) }
    }

    fun updateEditingPlayIntegrityUrl(newUrl: String) {
    }

    fun updateEditingKeyAttestationUrl(newUrl: String) {
    }

    fun saveApiEndpoints() {
        _uiState.update { it.copy(isLoading = false, saveSuccess = true, errorMessage = null) }
    }

    private fun isValidUrlOrEmpty(url: String): Boolean {
        if (url.isBlank()) {
            return true
        }
        return try {
            URL(url)
            true
        } catch (e: MalformedURLException) {
            false
        }
    }

    fun resetSaveSuccess() {
        _uiState.update { it.copy(saveSuccess = false) }
    }
}
