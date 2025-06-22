package dev.keiji.deviceintegrity.provider.impl

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import androidx.biometric.BiometricManager
import android.os.Build
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mock
import org.mockito.Mockito.`when`
import org.mockito.MockitoAnnotations
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [Build.VERSION_CODES.P]) // Default SDK for most tests
class DeviceSecurityStateProviderImplTest {

    @Mock
    private lateinit var mockContext: Context

    @Mock
    private lateinit var mockKeyguardManager: KeyguardManager

    @Mock
    private lateinit var mockBiometricManager: BiometricManager

    @Mock
    private lateinit var mockPackageManager: PackageManager

    private lateinit var deviceSecurityStateProvider: DeviceSecurityStateProviderImpl

    @Before
    fun setUp() {
        MockitoAnnotations.openMocks(this)

        `when`(mockContext.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(mockKeyguardManager)
        `when`(mockContext.packageManager).thenReturn(mockPackageManager)

        // Instantiate with the internal constructor, injecting the mock BiometricManager
        deviceSecurityStateProvider = DeviceSecurityStateProviderImpl(mockContext, mockBiometricManager)
    }

    @Test
    fun `isDeviceLockEnabled returns true when KeyguardManager_isDeviceSecure returns true`() {
        `when`(mockKeyguardManager.isDeviceSecure).thenReturn(true)
        assertEquals(true, deviceSecurityStateProvider.isDeviceLockEnabled)
    }

    @Test
    fun `isDeviceLockEnabled returns false when KeyguardManager_isDeviceSecure returns false`() {
        `when`(mockKeyguardManager.isDeviceSecure).thenReturn(false)
        assertEquals(false, deviceSecurityStateProvider.isDeviceLockEnabled)
    }

    @Test
    fun `isBiometricsEnabled returns true when BiometricManager_canAuthenticate BIOMETRIC_WEAK or STRONG returns BIOMETRIC_SUCCESS`() {
        val authenticators = BiometricManager.Authenticators.BIOMETRIC_WEAK or BiometricManager.Authenticators.BIOMETRIC_STRONG
        `when`(mockBiometricManager.canAuthenticate(authenticators))
            .thenReturn(BiometricManager.BIOMETRIC_SUCCESS)
        assertEquals(true, deviceSecurityStateProvider.isBiometricsEnabled)
    }

    @Test
    fun `isBiometricsEnabled returns false when BiometricManager_canAuthenticate BIOMETRIC_WEAK or STRONG returns ERROR`() {
        val authenticators = BiometricManager.Authenticators.BIOMETRIC_WEAK or BiometricManager.Authenticators.BIOMETRIC_STRONG
        `when`(mockBiometricManager.canAuthenticate(authenticators))
            .thenReturn(BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE) // Or any other error
        assertEquals(false, deviceSecurityStateProvider.isBiometricsEnabled)
    }

    @Test
    fun `hasClass3Authenticator returns true when BiometricManager_canAuthenticate BIOMETRIC_STRONG returns BIOMETRIC_SUCCESS`() {
        `when`(mockBiometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG))
            .thenReturn(BiometricManager.BIOMETRIC_SUCCESS)
        assertEquals(true, deviceSecurityStateProvider.hasClass3Authenticator)
    }

    @Test
    fun `hasClass3Authenticator returns false when BiometricManager_canAuthenticate BIOMETRIC_STRONG returns ERROR`() {
        `when`(mockBiometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG))
            .thenReturn(BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE) // Or any other error
        assertEquals(false, deviceSecurityStateProvider.hasClass3Authenticator)
    }

    @Test
    @Config(sdk = [Build.VERSION_CODES.P])
    fun `hasStrongBox returns true when PackageManager_hasSystemFeature FEATURE_STRONGBOX_KEYSTORE returns true on P and above`() {
        `when`(mockPackageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)).thenReturn(true)
        assertEquals(true, deviceSecurityStateProvider.hasStrongBox)
    }

    @Test
    @Config(sdk = [Build.VERSION_CODES.P])
    fun `hasStrongBox returns false when PackageManager_hasSystemFeature FEATURE_STRONGBOX_KEYSTORE returns false on P and above`() {
        `when`(mockPackageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)).thenReturn(false)
        assertEquals(false, deviceSecurityStateProvider.hasStrongBox)
    }

    @Test
    @Config(sdk = [Build.VERSION_CODES.M]) // Test for SDK < P
    fun `hasStrongBox returns false when sdk is less than P`() {
        assertEquals(false, deviceSecurityStateProvider.hasStrongBox)
    }
}
