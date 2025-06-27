package dev.keiji.deviceintegrity.provider.impl

import android.os.Build
import dev.keiji.deviceintegrity.provider.contract.DeviceInfoProvider

class DeviceInfoProviderImpl : DeviceInfoProvider {
    override val BRAND: String = Build.BRAND
    override val MODEL: String = Build.MODEL
    override val BASE_OS: String = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) Build.VERSION.BASE_OS else ""
    override val VERSION_INCREMENTAL: String = Build.VERSION.INCREMENTAL
    override val VERSION_RELEASE: String = Build.VERSION.RELEASE
    override val SDK_INT: Int = Build.VERSION.SDK_INT
    override val DISPLAY: String = Build.DISPLAY
    override val DEVICE: String = Build.DEVICE
    override val PRODUCT: String = Build.PRODUCT
    override val MANUFACTURER: String = Build.MANUFACTURER
    override val HARDWARE: String = Build.HARDWARE
    override val ID: String = Build.ID
    override val HOST: String = Build.HOST
    override val TAGS: String = Build.TAGS
    override val TYPE: String = Build.TYPE
    override val USER: String = Build.USER
    override val BOARD: String = Build.BOARD
    override val BOOTLOADER: String = Build.BOOTLOADER
    override val FINGERPRINT: String = Build.FINGERPRINT
    override val TIME: Long = Build.TIME
    override val SECURITY_PATCH: String = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) Build.VERSION.SECURITY_PATCH else "N/A"
}
