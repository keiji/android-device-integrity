package dev.keiji.deviceintegrity.di

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dev.keiji.deviceintegrity.ui.nav.contract.ApiEndpointSettingsNavigator
import dev.keiji.deviceintegrity.ui.nav.impl.ApiEndpointSettingsNavigatorImpl
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object NavigationModule {

    @Singleton
    @Provides
    fun provideApiEndpointSettingsNavigator(): ApiEndpointSettingsNavigator {
        return ApiEndpointSettingsNavigatorImpl()
    }
}
