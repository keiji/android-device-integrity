package dev.keiji.deviceintegrity.ui.main.settings

import android.os.Build
import androidx.lifecycle.ViewModel
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.deviceintegrity.provider.contract.AppInfoProvider
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject

@HiltViewModel
class SettingsViewModel @Inject constructor(
    appInfoProvider: AppInfoProvider
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        SettingsUiState(
            appVersionName = appInfoProvider.getAppVersionName(),
            appVersionCode = appInfoProvider.getAppVersionCode(),
            osVersion = Build.VERSION.RELEASE,
            securityPatchLevel = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                Build.VERSION.SECURITY_PATCH
            } else {
                "N/A" // Marshmallow以前はSECURITY_PATCHがない
            }
        )
    )
    val uiState: StateFlow<SettingsUiState> = _uiState.asStateFlow()
}
