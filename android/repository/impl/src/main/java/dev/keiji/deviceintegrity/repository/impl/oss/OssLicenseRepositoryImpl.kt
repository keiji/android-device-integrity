package dev.keiji.deviceintegrity.repository.impl.oss

import android.content.res.AssetManager
import dev.keiji.deviceintegrity.repository.contract.oss.OssLicenseRepository
import dev.keiji.deviceintegrity.repository.contract.oss.PomInfo
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStreamReader

class OssLicenseRepositoryImpl(
    private val assetManager: AssetManager,
    private val filenames: List<String>,
    private val dispatcher: CoroutineDispatcher
) : OssLicenseRepository {

    private val json = Json { ignoreUnknownKeys = true }

    @Throws(IOException::class)
    override suspend fun loadLicenses(): List<PomInfo> = withContext(dispatcher) {
        val allPomInfos = mutableListOf<PomInfo>()
        for (filename in filenames) {
            val jsonString = assetManager.open(filename).use { inputStream ->
                BufferedReader(InputStreamReader(inputStream)).use { reader ->
                    reader.readText()
                }
            }
            // Assuming each JSON file is an array of PomInfo objects
            val pomInfosInFile = json.decodeFromString<List<PomInfo>>(jsonString)
            allPomInfos.addAll(pomInfosInFile)
        }
        allPomInfos
    }
}
