package dev.keiji.deviceintegrity.provider.impl

import org.junit.Assert.assertFalse
import org.junit.Before
import org.junit.Test

class DeviceSecurityStateProviderImplTest {

    private lateinit var deviceSecurityStateProvider: DeviceSecurityStateProviderImpl

    @Before
    fun setUp() {
        deviceSecurityStateProvider = DeviceSecurityStateProviderImpl()
    }

    @Test
    fun `isDeviceLockEnabled returns false by default`() {
        assertFalse(deviceSecurityStateProvider.isDeviceLockEnabled)
    }

    @Test
    fun `isBiometricsEnabled returns false by default`() {
        assertFalse(deviceSecurityStateProvider.isBiometricsEnabled)
    }

    @Test
    fun `hasClass3Authenticator returns false by default`() {
        assertFalse(deviceSecurityStateProvider.hasClass3Authenticator)
    }

    @Test
    fun `hasStrongBox returns false by default`() {
        assertFalse(deviceSecurityStateProvider.hasStrongBox)
    }
}
