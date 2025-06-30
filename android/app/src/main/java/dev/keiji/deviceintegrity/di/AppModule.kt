package dev.keiji.deviceintegrity.di

import com.jakewharton.retrofit2.converter.kotlinx.serialization.asConverterFactory
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dev.keiji.deviceintegrity.AppInfoProviderImpl
import dev.keiji.deviceintegrity.provider.contract.AppInfoProvider
import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import dev.keiji.deviceintegrity.provider.contract.DeviceInfoProvider
import dev.keiji.deviceintegrity.provider.contract.DeviceSecurityStateProvider
import dev.keiji.deviceintegrity.provider.contract.GooglePlayDeveloperServiceInfoProvider
import dev.keiji.deviceintegrity.provider.impl.DeviceInfoProviderImpl
import dev.keiji.deviceintegrity.provider.impl.DeviceSecurityStateProviderImpl
import dev.keiji.deviceintegrity.provider.impl.GooglePlayDeveloperServiceInfoProviderImpl
import javax.inject.Singleton
import android.content.res.AssetManager
import dev.keiji.deviceintegrity.provider.AssetInputStreamProviderImpl
import dev.keiji.provider.contract.AssetInputStreamProvider
import kotlinx.coroutines.Dispatchers

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Provides
    @Singleton
    fun provideAppInfoProvider(): AppInfoProvider {
        return AppInfoProviderImpl(dev.keiji.deviceintegrity.BuildConfig.DEBUG)
    }

    @Provides
    @Singleton
    fun provideDeviceInfoProvider(): DeviceInfoProvider {
        return DeviceInfoProviderImpl()
    }

    @Provides
    @Singleton
    fun provideDeviceSecurityStateProvider(
        @ApplicationContext context: Context
    ): DeviceSecurityStateProvider {
        return DeviceSecurityStateProviderImpl(context)
    }

    @Provides
    @Singleton
    fun provideAssetManager(
        @ApplicationContext context: Context
    ): AssetManager {
        return context.assets
    }

    @Provides
    @Singleton
    fun provideAssetInputStreamProvider(
        assetManager: AssetManager
    ): AssetInputStreamProvider {
        return AssetInputStreamProviderImpl(assetManager)
    }

    @Provides
    @Singleton
    fun provideGooglePlayDeveloperServiceInfoProvider(
        @ApplicationContext context: Context
    ): GooglePlayDeveloperServiceInfoProvider {
        return GooglePlayDeveloperServiceInfoProviderImpl(Dispatchers.IO, context)
    }
}
