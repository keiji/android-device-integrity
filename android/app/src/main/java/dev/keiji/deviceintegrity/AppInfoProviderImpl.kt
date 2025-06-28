package dev.keiji.deviceintegrity

import dev.keiji.deviceintegrity.provider.contract.AppInfoProvider
import javax.inject.Inject

class AppInfoProviderImpl @Inject constructor(
    private val isDebug: Boolean
) : AppInfoProvider {

    override fun getAppVersionName(): String {
        return BuildConfig.VERSION_NAME
    }

    override fun getAppVersionCode(): Long {
        return BuildConfig.VERSION_CODE.toLong()
    }

    override val isDebugBuild: Boolean
        get() = isDebug
}
