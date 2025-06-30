package dev.keiji.deviceintegrity.provider.contract

interface GooglePlayDeveloperServiceInfoProvider {
    suspend fun provide(): GooglePlayDeveloperServiceInfo?
}
