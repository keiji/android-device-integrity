package dev.keiji.deviceintegrity.ui.license

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.deviceintegrity.repository.contract.oss.OssLicenseRepository // Changed
import dev.keiji.deviceintegrity.repository.contract.oss.PomInfo // Changed
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

data class LicenseInfo(
    val softwareName: String,
    val licenseName: String,
    val copyrightHolder: String,
    val licenseUrl: String? // PomInfo.url can be null
)

@HiltViewModel
class LicenseViewModel @Inject constructor(
    private val ossLicenseRepository: OssLicenseRepository // Changed
) : ViewModel() {

    private val _licenses = MutableStateFlow<List<LicenseInfo>>(emptyList())
    val licenses: StateFlow<List<LicenseInfo>> = _licenses.asStateFlow()

    // dummyLicenseData removed

    init {
        loadLicenses()
    }

    private fun loadLicenses() {
        viewModelScope.launch {
            try {
                val pomInfos = ossLicenseRepository.loadLicenses() // Changed
                _licenses.value = pomInfos.map { pomInfo ->
                    LicenseInfo(
                        softwareName = pomInfo.name,
                        licenseName = pomInfo.licenses.firstOrNull()?.name ?: "N/A",
                        copyrightHolder = pomInfo.organization?.name
                            ?: pomInfo.developers.firstOrNull()?.name ?: "N/A",
                        licenseUrl = pomInfo.url
                    )
                }
            } catch (e: Exception) {
                // Log the exception e
                _licenses.value = emptyList() // Set empty list on error
            }
        }
    }
}
