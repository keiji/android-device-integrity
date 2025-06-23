package dev.keiji.deviceintegrity.ui.main.settings

import dagger.hilt.EntryPoint
import dagger.hilt.InstallIn
import dagger.hilt.android.components.ActivityComponent
import dev.keiji.deviceintegrity.ui.nav.contract.ApiEndpointSettingsNavigator

@EntryPoint
@InstallIn(ActivityComponent::class)
interface MainHiltEntryPoint {
    fun getApiEndpointSettingsNavigator(): ApiEndpointSettingsNavigator
}
