package dev.keiji.deviceintegrity.provider.contract

interface DeviceInfoProvider {
    val BRAND: String
    val MODEL: String
    val BASE_OS: String
    val VERSION_INCREMENTAL: String
    val VERSION_RELEASE: String
    val SDK_INT: Int
    val DISPLAY: String
    val DEVICE: String
    val PRODUCT: String
    val MANUFACTURER: String
    val HARDWARE: String
    val ID: String
    val HOST: String
    val TAGS: String
    val TYPE: String
    val USER: String
    val BOARD: String
    val BOOTLOADER: String
    val FINGERPRINT: String
    val TIME: Long
    val SECURITY_PATCH: String

    val isKeyAttestationAvailable: Boolean
    val isEcdhKeyAttestationAvailable: Boolean
}
