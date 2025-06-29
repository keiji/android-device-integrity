package dev.keiji.deviceintegrity.provider

import android.content.res.AssetManager
import dev.keiji.provider.contract.AssetInputStreamProvider
import java.io.InputStream
import javax.inject.Inject

class AssetInputStreamProviderImpl @Inject constructor(
    private val assetManager: AssetManager
) : AssetInputStreamProvider {

    companion object {
        private const val LICENSE_FILE_NAME = "licenses.json"
    }

    override fun openLicense(): InputStream {
        return open(LICENSE_FILE_NAME)
    }

    private fun open(fileName: String): InputStream {
        return assetManager.open(fileName)
    }
}
