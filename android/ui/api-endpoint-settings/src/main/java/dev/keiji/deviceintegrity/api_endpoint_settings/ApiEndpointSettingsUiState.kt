package dev.keiji.deviceintegrity.api_endpoint_settings

data class ApiEndpointSettingsUiState(
    val currentPlayIntegrityUrl: String = "",
    val editingPlayIntegrityUrl: String = "",
    val currentKeyAttestationUrl: String = "",
    val editingKeyAttestationUrl: String = "",
    val errorMessage: String? = null, // For validation errors.
    val isLoading: Boolean = false, // To show a progress indicator during save.
    val saveSuccess: Boolean = false // To indicate successful save, e.g., to close screen or show message.
)
