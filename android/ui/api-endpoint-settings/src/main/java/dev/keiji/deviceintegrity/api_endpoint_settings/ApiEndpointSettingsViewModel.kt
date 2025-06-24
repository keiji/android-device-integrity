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
        preferencesRepository.apiEndpointUrl
            .onEach { persistedUrl ->
                _uiState.update { currentState ->
                    currentState.copy(
                        currentUrl = persistedUrl ?: "",
                        // Initialize editingUrl only if it's the first load or matches current (or empty)
                        // This prevents overwriting user's input if they are editing when persistedUrl changes externally
                        editingUrl = if (currentState.editingUrl.isEmpty() || currentState.editingUrl == currentState.currentUrl) {
                            persistedUrl ?: ""
                        } else {
                            currentState.editingUrl
                        },
                        isLoading = false, // Reset loading state on new data
                        saveSuccess = false // Reset save success state
                    )
                }
            }
            .launchIn(viewModelScope)
    }

    fun updateEditingUrl(newUrl: String) {
        if (newUrl.all { it.isLetterOrDigit() || it in ValidationConstants.ALLOWED_URL_CHARACTERS }) {
            _uiState.update {
                it.copy(
                    editingUrl = newUrl,
                    errorMessage = null, // Clear error when user types
                    saveSuccess = false // Reset save success if user starts editing again
                )
            }
        }
    }

    fun saveApiEndpoint() {
        println("saveApiEndpoint called")
        val urlToSave = _uiState.value.editingUrl

        _uiState.update { it.copy(isLoading = true, errorMessage = null, saveSuccess = false) }

        viewModelScope.launch {
            try {
                // Validate URL format
                URL(urlToSave) // This will throw MalformedURLException if invalid

                println("saveApiEndpointUrl start")

                preferencesRepository.saveApiEndpointUrl(urlToSave)

                println("saveApiEndpointUrl end")

                _uiState.update {
                    it.copy(
                        isLoading = false,
                        currentUrl = urlToSave, // Reflect saved URL
                        saveSuccess = true,
                        errorMessage = null
                    )
                }
            } catch (e: MalformedURLException) {
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        errorMessage = "Invalid URL format",
                        saveSuccess = false
                    )
                }
            } catch (e: Exception) {
                // Handle other potential errors during save
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        errorMessage = "Failed to save URL: ${e.localizedMessage}",
                        saveSuccess = false
                    )
                }
            }
        }
    }

    fun resetSaveSuccess() {
        _uiState.update { it.copy(saveSuccess = false) }
    }
}
