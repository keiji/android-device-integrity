package dev.keiji.deviceintegrity.ui.menu

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.deviceintegrity.provider.contract.AppInfoProvider
import dev.keiji.deviceintegrity.provider.contract.DeviceInfoProvider
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
    private val deviceInfoProvider: DeviceInfoProvider,
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        SettingsUiState(
            appVersionName = appInfoProvider.getAppVersionName(),
            appVersionCode = appInfoProvider.getAppVersionCode(),
            deviceName = "${deviceInfoProvider.BRAND} ${deviceInfoProvider.MODEL}",
            osVersion = deviceInfoProvider.VERSION_RELEASE,
            securityPatchLevel = deviceInfoProvider.SECURITY_PATCH
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

    fun openSupportSiteUrl() {
        viewModelScope.launch {
            _eventChannel.send(SettingsUiEvent.OpenUrl(urlProvider.aboutAppUrl))
        }
    }
}
