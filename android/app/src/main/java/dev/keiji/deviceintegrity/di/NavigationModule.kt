package dev.keiji.deviceintegrity.di

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dev.keiji.deviceintegrity.ui.nav.contract.ApiEndpointSettingsNavigator
import dev.keiji.deviceintegrity.ui.nav.impl.ApiEndpointSettingsNavigatorImpl
import dev.keiji.deviceintegrity.ui.nav.contract.LicenseNavigator // Updated import
import dev.keiji.deviceintegrity.ui.nav.impl.LicenseNavigatorImpl // Updated import
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object NavigationModule {

    @Singleton
    @Provides
    fun provideApiEndpointSettingsNavigator(): ApiEndpointSettingsNavigator {
        return ApiEndpointSettingsNavigatorImpl()
    }

    @Singleton
    @Provides
    fun provideLicenseNavigator(): LicenseNavigator { // Updated return type and method name
        return LicenseNavigatorImpl() // Updated instantiation
    }
}
