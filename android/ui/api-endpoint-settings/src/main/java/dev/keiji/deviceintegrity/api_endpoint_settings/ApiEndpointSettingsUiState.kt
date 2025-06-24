package dev.keiji.deviceintegrity.api_endpoint_settings

data class ApiEndpointSettingsUiState(
    val currentUrl: String = "", // Persisted URL, TextField will be initialized with this.
    val editingUrl: String = "", // URL currently being edited in the TextField.
    val errorMessage: String? = null, // For validation errors.
    val isLoading: Boolean = false, // To show a progress indicator during save.
    val saveSuccess: Boolean = false // To indicate successful save, e.g., to close screen or show message.
)
