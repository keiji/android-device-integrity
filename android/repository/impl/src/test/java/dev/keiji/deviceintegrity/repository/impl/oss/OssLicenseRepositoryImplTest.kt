package dev.keiji.deviceintegrity.repository.impl.oss

import android.content.res.AssetManager
import dev.keiji.deviceintegrity.repository.contract.oss.Developer
import dev.keiji.deviceintegrity.repository.contract.oss.License
import dev.keiji.deviceintegrity.repository.contract.oss.Organization
import dev.keiji.deviceintegrity.repository.contract.oss.OssLicense
import dev.keiji.deviceintegrity.repository.contract.oss.OssLicenseRepository
import dev.keiji.deviceintegrity.repository.contract.oss.PomInfo
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Before
import org.junit.Test
import org.mockito.Mock
import org.mockito.MockitoAnnotations
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.whenever
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.nio.charset.StandardCharsets
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@ExperimentalCoroutinesApi
class OssLicenseRepositoryImplTest {

    @Mock
    private lateinit var mockAssetManager: AssetManager

    private lateinit var repository: OssLicenseRepository
    private val testDispatcher = StandardTestDispatcher()

    private val json = Json { ignoreUnknownKeys = true; prettyPrint = true }

    @Before
    fun setUp() {
        MockitoAnnotations.openMocks(this)
    }

    private fun createInputStream(content: String): InputStream {
        return ByteArrayInputStream(content.toByteArray(StandardCharsets.UTF_8))
    }

    private val samplePomInfo1 = PomInfo(
        groupId = "com.example",
        artifactId = "library1",
        version = "1.0.0",
        name = "Example Library 1",
        url = "http://example.com/library1",
        licenses = listOf(License(name = "Apache 2.0", url = "http://www.apache.org/licenses/LICENSE-2.0.txt")),
        developers = listOf(Developer(name = "Developer 1", url = "http://example.com/dev1")),
        organization = Organization(name = "Example Org", url = "http://example.com/org"),
        dependencies = listOf("com.example:core:1.0"),
        depth = 0
    )
    private val samplePomInfo2 = PomInfo(
        groupId = "com.example",
        artifactId = "library2",
        version = "2.0.0",
        name = "Example Library 2",
        url = "http://example.com/library2",
        licenses = listOf(License(name = "MIT", url = "http://opensource.org/licenses/MIT")),
        developers = emptyList(),
        organization = null,
        dependencies = emptyList(),
        depth = 0
    )

    @Test
    fun `loadLicenses concatenates PomInfo from multiple files`() = runTest(testDispatcher) {
        val jsonContent1 =
            json.encodeToString(OssLicense(settings = null, pomList = listOf(samplePomInfo1)))
        val jsonContent2 =
            json.encodeToString(OssLicense(settings = null, pomList = listOf(samplePomInfo2)))

        whenever(mockAssetManager.open("licenses/license1.json")).doReturn(createInputStream(jsonContent1))
        whenever(mockAssetManager.open("licenses/license2.json")).doReturn(createInputStream(jsonContent2))

        repository = OssLicenseRepositoryImpl(mockAssetManager, listOf("licenses/license1.json", "licenses/license2.json"), testDispatcher)

        val expectedPomInfos = listOf(samplePomInfo1, samplePomInfo2)
        val actualPomInfos = repository.loadLicenses()
        assertEquals(expectedPomInfos.size, actualPomInfos.size)
        assertEquals(expectedPomInfos, actualPomInfos)
    }

    @Test
    fun `loadLicenses handles single file`() = runTest(testDispatcher) {
        val jsonContent =
            json.encodeToString(OssLicense(settings = null, pomList = listOf(samplePomInfo1)))
        whenever(mockAssetManager.open("licenses/single.json")).doReturn(createInputStream(jsonContent))

        repository = OssLicenseRepositoryImpl(mockAssetManager, listOf("licenses/single.json"), testDispatcher)
        val expectedPomInfos = listOf(samplePomInfo1)
        val actualPomInfos = repository.loadLicenses()
        assertEquals(expectedPomInfos, actualPomInfos)
    }

    @Test
    fun `loadLicenses handles empty file list`() = runTest(testDispatcher) {
        repository = OssLicenseRepositoryImpl(mockAssetManager, emptyList(), testDispatcher)
        val actualPomInfos = repository.loadLicenses()
        assertTrue(actualPomInfos.isEmpty(), "List of PomInfo should be empty")
    }

    @Test(expected = IOException::class)
    fun `loadLicenses throws IOException when file does not exist`() = runTest(testDispatcher) {
        whenever(mockAssetManager.open("nonexistent.json")).thenThrow(IOException("File not found"))
        repository = OssLicenseRepositoryImpl(mockAssetManager, listOf("nonexistent.json"), testDispatcher)
        repository.loadLicenses() // This should throw IOException
    }
}
