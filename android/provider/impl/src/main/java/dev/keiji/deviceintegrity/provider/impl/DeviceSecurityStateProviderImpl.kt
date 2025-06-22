package dev.keiji.deviceintegrity.provider.impl

import dev.keiji.deviceintegrity.provider.contract.DeviceSecurityStateProvider

class DeviceSecurityStateProviderImpl : DeviceSecurityStateProvider {
    override val isDeviceLockEnabled: Boolean
        get() = false // TODO: Implement actual logic
    override val isBiometricsEnabled: Boolean
        get() = false // TODO: Implement actual logic
    override val hasClass3Authenticator: Boolean
        get() = false // TODO: Implement actual logic
    override val hasStrongBox: Boolean
        get() = false // TODO: Implement actual logic
}
