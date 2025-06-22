package dev.keiji.deviceintegrity.provider.impl

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.biometric.BiometricManager
import dev.keiji.deviceintegrity.provider.contract.DeviceSecurityStateProvider

class DeviceSecurityStateProviderImpl internal constructor(
    private val context: Context,
    private val biometricManagerInstance: BiometricManager? // Nullable for default constructor
) : DeviceSecurityStateProvider {

    // Public constructor for normal instantiation
    constructor(context: Context) : this(context, null)

    // Internal property to get BiometricManager, uses injected one if available
    internal val resolvedBiometricManager: BiometricManager by lazy {
        biometricManagerInstance ?: BiometricManager.from(context)
    }

    override val isDeviceLockEnabled: Boolean
        get() {
            val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            return keyguardManager.isDeviceSecure
        }

    override val isBiometricsEnabled: Boolean
        get() {
            val authenticators = BiometricManager.Authenticators.BIOMETRIC_WEAK or BiometricManager.Authenticators.BIOMETRIC_STRONG
            return resolvedBiometricManager.canAuthenticate(authenticators) == BiometricManager.BIOMETRIC_SUCCESS
        }

    override val hasClass3Authenticator: Boolean
        get() {
            return resolvedBiometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
        }

    override val hasStrongBox: Boolean
        get() {
            return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
            } else {
                false
            }
        }
}
