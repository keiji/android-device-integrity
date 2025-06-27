package dev.keiji.deviceintegrity.ui.main.settings

import android.os.Build
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.deviceintegrity.provider.contract.AppInfoProvider
import dev.keiji.deviceintegrity.provider.contract.UrlProvider
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

sealed class SettingsUiEvent {
    data class OpenUrl(val url: String) : SettingsUiEvent()
}

@HiltViewModel
class SettingsViewModel @Inject constructor(
    appInfoProvider: AppInfoProvider,
    private val urlProvider: UrlProvider,
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

    private val _eventChannel = Channel<SettingsUiEvent>()
    val eventFlow = _eventChannel.receiveAsFlow()

    fun openTermsOfServiceUrl() {
        viewModelScope.launch {
            _eventChannel.send(SettingsUiEvent.OpenUrl(urlProvider.termsOfServiceUrl))
        }
    }

    fun openPrivacyPolicyUrl() {
        viewModelScope.launch {
            _eventChannel.send(SettingsUiEvent.OpenUrl(urlProvider.privacyPolicyUrl))
        }
    }

    fun openAboutAppUrl() {
        viewModelScope.launch {
            _eventChannel.send(SettingsUiEvent.OpenUrl(urlProvider.aboutAppUrl))
        }
    }
}
