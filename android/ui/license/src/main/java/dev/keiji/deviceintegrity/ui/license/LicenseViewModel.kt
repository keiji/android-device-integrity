package dev.keiji.deviceintegrity.ui.license

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.provider.contract.AssetInputStreamProvider
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
// import java.io.InputStreamReader // No longer needed for now
import javax.inject.Inject

// LicenseInfo data class moved here
data class LicenseInfo(
    val softwareName: String,
    val licenseName: String,
    val copyrightHolder: String,
    val licenseUrl: String
)

@HiltViewModel
class LicenseViewModel @Inject constructor(
    private val assetInputStreamProvider: AssetInputStreamProvider
) : ViewModel() {

    // private val _licenseText = MutableStateFlow<String?>(null) // Removed
    // val licenseText: StateFlow<String?> = _licenseText.asStateFlow() // Removed

    private val _licenses = MutableStateFlow<List<LicenseInfo>>(emptyList())
    val licenses: StateFlow<List<LicenseInfo>> = _licenses.asStateFlow()

    // Dummy data similar to what was in LicenseScreen.kt
    private val dummyLicenseData = List(10) { index ->
        LicenseInfo(
            softwareName = "Software Name ${index + 1} from ViewModel", // Added "from ViewModel" for clarity
            licenseName = "Apache License 2.0",
            copyrightHolder = "Copyright Holder ${index + 1}",
            licenseUrl = "https://www.apache.org/licenses/LICENSE-2.0"
        )
    }

    init {
        loadLicenses()
    }

    private fun loadLicenses() {
        viewModelScope.launch {
            try {
                // Open the license file to ensure it's accessible, but don't use its content for now
                val inputStream = assetInputStreamProvider.openLicense()
                // val reader = InputStreamReader(inputStream) // Not reading text for now
                // val textContent = reader.readText() // Not reading text for now
                // reader.close()
                inputStream.close()
                // Log.d("LicenseViewModel", "License file opened successfully. Content not used yet.")

                // For now, just use dummy data
                _licenses.value = dummyLicenseData

            } catch (e: Exception) {
                // Handle error, e.g., by setting an error state or logging
                // Log.e("LicenseViewModel", "Error loading license file, using dummy data as fallback", e)
                _licenses.value = dummyLicenseData // Fallback to dummy data on error too
            }
        }
    }
}
