package dev.keiji.deviceintegrity.provider.contract

interface AppInfoProvider {
    fun getAppVersionName(): String
    fun getAppVersionCode(): Long
}
