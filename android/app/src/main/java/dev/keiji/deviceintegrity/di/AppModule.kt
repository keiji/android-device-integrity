package dev.keiji.deviceintegrity.di

import com.jakewharton.retrofit2.converter.kotlinx.serialization.asConverterFactory
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dev.keiji.deviceintegrity.AppInfoProviderImpl
import dev.keiji.deviceintegrity.provider.contract.AppInfoProvider
import dev.keiji.deviceintegrity.provider.contract.DeviceInfoProvider
import dev.keiji.deviceintegrity.provider.impl.DeviceInfoProviderImpl
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Provides
    @Singleton
    fun provideAppInfoProvider(
        impl: AppInfoProviderImpl
    ): AppInfoProvider {
        return impl
    }

    @Provides
    @Singleton
    fun provideDeviceInfoProvider(): DeviceInfoProvider {
        return DeviceInfoProviderImpl()
    }
}
