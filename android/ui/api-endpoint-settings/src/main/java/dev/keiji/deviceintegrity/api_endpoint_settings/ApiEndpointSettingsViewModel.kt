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
        preferencesRepository.playIntegrityVerifyApiEndpointUrl
            .onEach { persistedUrl ->
                _uiState.update { currentState ->
                    currentState.copy(
                        currentPlayIntegrityUrl = persistedUrl ?: "",
                        editingPlayIntegrityUrl = if (currentState.editingPlayIntegrityUrl.isEmpty() || currentState.editingPlayIntegrityUrl == currentState.currentPlayIntegrityUrl) {
                            persistedUrl ?: ""
                        } else {
                            currentState.editingPlayIntegrityUrl
                        },
                        isLoading = false,
                        saveSuccess = false
                    )
                }
            }
            .launchIn(viewModelScope)

        preferencesRepository.keyAttestationVerifyApiEndpointUrl
            .onEach { persistedUrl ->
                _uiState.update { currentState ->
                    currentState.copy(
                        currentKeyAttestationUrl = persistedUrl ?: "",
                        editingKeyAttestationUrl = if (currentState.editingKeyAttestationUrl.isEmpty() || currentState.editingKeyAttestationUrl == currentState.currentKeyAttestationUrl) {
                            persistedUrl ?: ""
                        } else {
                            currentState.editingKeyAttestationUrl
                        },
                        isLoading = false,
                        saveSuccess = false
                    )
                }
            }
            .launchIn(viewModelScope)
    }

    fun updateEditingPlayIntegrityUrl(newUrl: String) {
        if (newUrl.all { it.isLetterOrDigit() || it in ValidationConstants.ALLOWED_URL_CHARACTERS }) {
            _uiState.update {
                it.copy(
                    editingPlayIntegrityUrl = newUrl,
                    errorMessage = null,
                    saveSuccess = false
                )
            }
        }
    }

    fun updateEditingKeyAttestationUrl(newUrl: String) {
        if (newUrl.all { it.isLetterOrDigit() || it in ValidationConstants.ALLOWED_URL_CHARACTERS }) {
            _uiState.update {
                it.copy(
                    editingKeyAttestationUrl = newUrl,
                    errorMessage = null,
                    saveSuccess = false
                )
            }
        }
    }

    fun saveApiEndpoints() { // Renamed from saveApiEndpoint
        println("saveApiEndpoints called")
        val playIntegrityUrlToSave = _uiState.value.editingPlayIntegrityUrl
        val keyAttestationUrlToSave = _uiState.value.editingKeyAttestationUrl

        _uiState.update { it.copy(isLoading = true, errorMessage = null, saveSuccess = false) }

        viewModelScope.launch {
            try {
                // Validate URL formats
                if (playIntegrityUrlToSave.isNotBlank()) URL(playIntegrityUrlToSave)
                if (keyAttestationUrlToSave.isNotBlank()) URL(keyAttestationUrlToSave)

                println("savePlayIntegrityVerifyApiEndpointUrl start")
                if (playIntegrityUrlToSave.isNotBlank()) {
                    preferencesRepository.savePlayIntegrityVerifyApiEndpointUrl(playIntegrityUrlToSave)
                } else {
                    // If the field is blank, save an empty string or handle as per specific requirement
                    preferencesRepository.savePlayIntegrityVerifyApiEndpointUrl("")
                }
                println("savePlayIntegrityVerifyApiEndpointUrl end")

                println("saveKeyAttestationVerifyApiEndpointUrl start")
                if (keyAttestationUrlToSave.isNotBlank()) {
                    preferencesRepository.saveKeyAttestationVerifyApiEndpointUrl(keyAttestationUrlToSave)
                } else {
                    // If the field is blank, save an empty string or handle as per specific requirement
                    preferencesRepository.saveKeyAttestationVerifyApiEndpointUrl("")
                }
                println("saveKeyAttestationVerifyApiEndpointUrl end")

                _uiState.update {
                    it.copy(
                        isLoading = false,
                        currentPlayIntegrityUrl = playIntegrityUrlToSave,
                        currentKeyAttestationUrl = keyAttestationUrlToSave,
                        saveSuccess = true,
                        errorMessage = null
                    )
                }
            } catch (e: MalformedURLException) {
                // Check which URL (if any non-blank) caused the error
                val playIntegrityError = playIntegrityUrlToSave.isNotBlank() && !isValidUrlOrEmpty(playIntegrityUrlToSave)
                val keyAttestationError = keyAttestationUrlToSave.isNotBlank() && !isValidUrlOrEmpty(keyAttestationUrlToSave)

                val message = when {
                    playIntegrityError && keyAttestationError -> "Invalid format for both URLs"
                    playIntegrityError -> "Invalid format for Play Integrity URL"
                    keyAttestationError -> "Invalid format for Key Attestation URL"
                    else -> "Invalid URL format" // Fallback, should ideally not happen if logic is correct
                }
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        errorMessage = message,
                        saveSuccess = false
                    )
                }
            } catch (e: Exception) {
                // Handle other potential errors during save
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        errorMessage = "Failed to save URL(s): ${e.localizedMessage}",
                        saveSuccess = false
                    )
                }
            }
        }
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
