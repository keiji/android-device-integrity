package dev.keiji.provider.contract

import java.io.InputStream

interface AssetInputStreamProvider {
    fun openLicense(): InputStream
}
