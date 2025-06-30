package dev.keiji.deviceintegrity.ui.license

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.deviceintegrity.repository.contract.oss.OssLicenseRepository
import dev.keiji.deviceintegrity.repository.contract.oss.PomInfo
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
    private val ossLicenseRepository: OssLicenseRepository
) : ViewModel() {

    private val _licenses = MutableStateFlow<List<LicenseInfo>>(emptyList())
    val licenses: StateFlow<List<LicenseInfo>> = _licenses.asStateFlow()

    init {
        loadLicenses()
    }

    private fun loadLicenses() {
        viewModelScope.launch {
            try {
                val pomInfos = ossLicenseRepository.loadLicenses()
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
                _licenses.value = emptyList()
            }
        }
    }
}
