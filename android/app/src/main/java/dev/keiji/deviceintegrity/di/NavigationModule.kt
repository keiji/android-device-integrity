package dev.keiji.deviceintegrity.di

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dev.keiji.deviceintegrity.ui.nav.contract.AgreementNavigator
import dev.keiji.deviceintegrity.ui.nav.contract.ApiEndpointSettingsNavigator
import dev.keiji.deviceintegrity.ui.nav.impl.AgreementNavigatorImpl
import dev.keiji.deviceintegrity.ui.nav.impl.ApiEndpointSettingsNavigatorImpl
import dev.keiji.deviceintegrity.ui.nav.contract.LicenseNavigator
import dev.keiji.deviceintegrity.ui.nav.impl.LicenseNavigatorImpl
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
    fun provideLicenseNavigator(): LicenseNavigator {
        return LicenseNavigatorImpl()
    }

    @Singleton
    @Provides
    fun provideAgreementNavigator(): AgreementNavigator {
        return AgreementNavigatorImpl()
    }
}
