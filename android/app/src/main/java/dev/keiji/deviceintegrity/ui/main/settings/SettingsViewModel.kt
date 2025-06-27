package dev.keiji.deviceintegrity.ui.main.settings

import androidx.lifecycle.ViewModel
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.keiji.deviceintegrity.provider.contract.DeviceInfoProvider
import javax.inject.Inject

@HiltViewModel
class SettingsViewModel @Inject constructor(
    private val deviceInfoProvider: DeviceInfoProvider
) : ViewModel() {

    val deviceName: String = "${deviceInfoProvider.BRAND} ${deviceInfoProvider.MODEL}"
    val osVersion: String = deviceInfoProvider.VERSION_RELEASE // OSバージョンもここで取得しておきます
}
