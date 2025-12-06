package dev.keiji.deviceintegrity.provider.contract

interface DeviceSecurityStateProvider {
    val isDeviceLockEnabled: Boolean
    val isBiometricsEnabled: Boolean
    val hasClass3Authenticator: Boolean
    val hasStrongBox: Boolean
    val isDevicePropertiesAttestationSupported: Boolean
}
