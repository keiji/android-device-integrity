package dev.keiji.deviceintegrity.ui.license

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.provider.contract.AssetInputStreamProvider
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

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

    private val _licenses = MutableStateFlow<List<LicenseInfo>>(emptyList())
    val licenses: StateFlow<List<LicenseInfo>> = _licenses.asStateFlow()

    private val dummyLicenseData = List(10) { index ->
        LicenseInfo(
            softwareName = "Software Name ${index + 1}", // " from ViewModel" removed
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
                val inputStream = assetInputStreamProvider.openLicense()
                inputStream.close()
                _licenses.value = dummyLicenseData
            } catch (e: Exception) {
                _licenses.value = dummyLicenseData
            }
        }
    }
}
