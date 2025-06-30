package dev.keiji.deviceintegrity.provider.impl.oss

import dev.keiji.deviceintegrity.provider.contract.oss.OssLicenseProvider
import dev.keiji.deviceintegrity.provider.contract.oss.PomInfo
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext

class OssLicenseProviderImpl(
    private val dispatcher: CoroutineDispatcher
) : OssLicenseProvider {
    override suspend fun loadLicenses(): List<PomInfo> = withContext(dispatcher) {
        // TODO: Implement actual license loading logic
        emptyList()
    }
}
